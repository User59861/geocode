import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage, type FullCreditReport } from "./storage";
import { z } from "zod";
import { fromError } from "zod-validation-error";
import { equifaxClient, type NormalizedCreditReport, type NormalizedTradeline, type EquifaxEnvironment } from "./equifax";
import { objectStorageService, ObjectNotFoundError } from "./objectStorage";
import { transformToExperianFormat } from "./experianFormatter";
import { normalizeAddress, type NormalizedAddress } from "./normalizeAddress";
import { pushToGitHub, pullFromGitHub, getSyncStatus } from "./githubSync";
import crypto from "crypto";
import type { ApiClient } from "@shared/schema";

declare global {
  namespace Express {
    interface Request {
      apiClient?: ApiClient;
    }
  }
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

function generateClientCredentials(): { clientId: string; clientSecret: string } {
  const clientId = `cli_${crypto.randomBytes(16).toString("hex")}`;
  const clientSecret = `sec_${crypto.randomBytes(32).toString("hex")}`;
  return { clientId, clientSecret };
}

function generateAccessToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

function maskSensitiveData(data: any): any {
  if (!data) return data;
  return { ...data };
}

const creditReportRequestSchema = z.object({
  firstName: z.string().optional().default(""),
  lastName: z.string().optional().default(""),
  middleName: z.string().optional(),
  ssn: z.string().optional().default(""),
  dateOfBirth: z.string().optional().default(""),
  address: z.object({
    street: z.string().optional().default(""),
    city: z.string().optional().default(""),
    state: z.string().optional().default(""),
    zipCode: z.string().optional().default(""),
  }).optional().default({}),
});

const prescreenRequestSchema = creditReportRequestSchema.extend({
  minScoreThreshold: z.number().min(300).max(850).optional(),
});

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  // OAuth Token Endpoint
  app.post("/api/oauth/token", async (req, res) => {
    const startTime = Date.now();
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      res.setHeader("WWW-Authenticate", 'Basic realm="API"');
      await storage.createApiRequestLog({
        endpoint: "/api/oauth/token",
        method: "POST",
        statusCode: 401,
        durationMs: Date.now() - startTime,
        errorMessage: "Missing or invalid Authorization header",
        ipAddress: req.ip || req.socket.remoteAddress,
      });
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    try {
      const base64Credentials = authHeader.slice(6);
      const credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
      const [clientId, clientSecret] = credentials.split(":");

      if (!clientId || !clientSecret) {
        res.setHeader("WWW-Authenticate", 'Basic realm="API"');
        return res.status(401).json({ error: "Invalid credentials format" });
      }

      const client = await storage.getApiClientByClientId(clientId);
      if (!client) {
        await storage.createApiRequestLog({
          endpoint: "/api/oauth/token",
          method: "POST",
          statusCode: 401,
          durationMs: Date.now() - startTime,
          errorMessage: "Invalid client credentials",
          ipAddress: req.ip || req.socket.remoteAddress,
        });
        res.setHeader("WWW-Authenticate", 'Basic realm="API"');
        return res.status(401).json({ error: "Invalid client credentials" });
      }

      if (!client.isEnabled) {
        return res.status(403).json({ error: "Client is disabled" });
      }

      const secretHash = hashSecret(clientSecret);
      if (secretHash !== client.clientSecretHash) {
        res.setHeader("WWW-Authenticate", 'Basic realm="API"');
        return res.status(401).json({ error: "Invalid client credentials" });
      }

      const accessToken = generateAccessToken();
      const tokenHash = hashToken(accessToken);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await storage.createApiToken({
        clientId: client.id,
        tokenHash,
        expiresAt,
      });

      await storage.touchApiClientLastUsed(client.id);

      const tokenResponse = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
      };

      await storage.createApiRequestLog({
        clientId: client.id,
        endpoint: "/api/oauth/token",
        method: "POST",
        statusCode: 200,
        durationMs: Date.now() - startTime,
        responseBody: { ...tokenResponse, access_token: tokenResponse.access_token.slice(0, 8) + "..." },
        ipAddress: req.ip || req.socket.remoteAddress,
      });

      return res.json(tokenResponse);
    } catch (error: any) {
      console.error("[OAuth] Token generation failed:", error.message);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // Bearer Token Auth Middleware
  const apiAuthMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.slice(7);
    const tokenHash = hashToken(token);
    
    const validToken = await storage.getValidApiToken(tokenHash);
    if (!validToken) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    await storage.touchApiTokenLastUsed(validToken.id);
    await storage.touchApiClientLastUsed(validToken.client.id);
    
    req.apiClient = validToken.client;
    next();
  };

  // Protected API: Credit Report
  app.post("/api/v1/credit-report", apiAuthMiddleware, async (req, res) => {
    const startTime = Date.now();
    const client = req.apiClient!;
    
    try {
      const parsed = creditReportRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        const error = fromError(parsed.error);
        await storage.createApiRequestLog({
          clientId: client.id,
          endpoint: "/api/v1/credit-report",
          method: "POST",
          statusCode: 400,
          durationMs: Date.now() - startTime,
          requestBody: maskSensitiveData(req.body),
          errorMessage: error.toString(),
          ipAddress: req.ip || req.socket.remoteAddress,
        });
        return res.status(400).json({ error: error.toString() });
      }

      const { firstName, lastName, middleName, ssn, dateOfBirth, address } = parsed.data;

      const report = await equifaxClient.getCreditReport({
        firstName,
        lastName,
        middleName,
        ssn,
        dateOfBirth,
        address: {
          street: address?.street || "",
          city: address?.city || "",
          state: address?.state || "",
          zipCode: address?.zipCode || "",
        },
      });

      // Save to normalized tables with raw response for reparsing
      const savedReport = await saveNormalizedReport(report, ssn || "", report.rawEquifaxResponse, {
        firstName,
        lastName,
        middleName,
        ssn,
        dateOfBirth,
        street: address?.street,
        city: address?.city,
        state: address?.state,
        zip: address?.zipCode,
        source: "api",
      });

      // Auto-upload PDF to Replit Object Storage whenever Equifax provides a link
      const activeEnv = equifaxClient.getActiveEnvironment();
      if (report.pdfPath && objectStorageService.isConfigured()) {
        try {
          console.log(`[API OAuth] Auto-uploading PDF for ${activeEnv} report from: ${report.pdfPath}`);
          const pdfBuffer = await equifaxClient.fetchPdf(report.pdfPath);
          const consumerName = `${firstName} ${lastName}`;
          const storageUploadResult = await objectStorageService.uploadPdf(
            pdfBuffer,
            consumerName,
            ssn || "",
            activeEnv
          );
          console.log(`[API OAuth] PDF Upload result:`, storageUploadResult);
          
          // Save PDF path to consumer record
          if (storageUploadResult.success && storageUploadResult.objectPath) {
            await storage.updateConsumer(savedReport.consumer.id, {
              pdfStoragePath: storageUploadResult.objectPath,
            });
            
            // Convert PDF to images and save to storage for persistent inline display
            try {
              console.log(`[API OAuth] Converting PDF to images for permanent storage...`);
              const { convertPdfToImages } = await import("./pdfConverter");
              const pages = await convertPdfToImages(pdfBuffer, 1.5);
              
              if (pages.length > 0) {
                const imagesResult = await objectStorageService.uploadPdfImages(
                  pages,
                  consumerName,
                  savedReport.consumer.id,
                  ssn || "",
                  activeEnv
                );
                
                if (imagesResult.success && imagesResult.objectPath) {
                  await storage.updateConsumer(savedReport.consumer.id, {
                    pdfImageStoragePath: imagesResult.objectPath,
                  });
                  console.log(`[API OAuth] PDF images saved: ${imagesResult.objectPath}`);
                }
              }
            } catch (imageError: any) {
              console.error(`[API OAuth] PDF image conversion failed:`, imageError.message);
            }
          }
        } catch (pdfError: any) {
          if (pdfError.message?.includes("406") && activeEnv === "sandbox") {
            console.log(`[API OAuth] Sandbox PDF not available (Equifax sandbox limitation)`);
          } else {
            console.error(`[API OAuth] PDF upload failed:`, pdfError.message);
          }
        }
      }

      const responseData = {
        success: true,
        consumer: savedReport.consumer,
        scores: savedReport.scores,
        tradelines: savedReport.tradelines,
        inquiries: savedReport.inquiries,
      };

      await storage.createApiRequestLog({
        clientId: client.id,
        endpoint: "/api/v1/credit-report",
        method: "POST",
        statusCode: 200,
        durationMs: Date.now() - startTime,
        requestBody: maskSensitiveData(req.body),
        responseBody: responseData,
        ipAddress: req.ip || req.socket.remoteAddress,
      });

      return res.json(responseData);
    } catch (error: any) {
      console.error("[API] Credit report request failed:", error.message);
      await storage.createApiRequestLog({
        clientId: client.id,
        endpoint: "/api/v1/credit-report",
        method: "POST",
        statusCode: 500,
        durationMs: Date.now() - startTime,
        requestBody: maskSensitiveData(req.body),
        errorMessage: error.message,
        ipAddress: req.ip || req.socket.remoteAddress,
      });
      return res.status(500).json({ error: error.message });
    }
  });

  // Protected API: Address Lookup (Geocoding)
  const addressLookupSchema = z.object({
    address: z.string().min(1, "Address is required"),
  });

  app.post("/api/v1/address", apiAuthMiddleware, async (req, res) => {
    const startTime = Date.now();
    const client = req.apiClient!;
    
    // Log every request immediately
    console.log("================================================================================");
    console.log("[API v1 Address] REQUEST RECEIVED");
    console.log(`[API v1 Address] Timestamp: ${new Date().toISOString()}`);
    console.log(`[API v1 Address] Client: ${client.name} (${client.clientId})`);
    console.log(`[API v1 Address] IP: ${req.ip || req.socket.remoteAddress}`);
    console.log(`[API v1 Address] Body:`, JSON.stringify(req.body, null, 2));
    console.log("================================================================================");
    
    try {
      const parsed = addressLookupSchema.safeParse(req.body);
      if (!parsed.success) {
        const error = fromError(parsed.error);
        await storage.createApiRequestLog({
          clientId: client.id,
          endpoint: "/api/v1/address",
          method: "POST",
          statusCode: 400,
          durationMs: Date.now() - startTime,
          requestBody: req.body,
          errorMessage: error.toString(),
          ipAddress: req.ip || req.socket.remoteAddress,
        });
        return res.status(400).json({ error: error.toString() });
      }

      const { address } = parsed.data;
      
      const results: {
        census: any;
        google: any;
        usps: any;
      } = {
        census: null,
        google: null,
        usps: null,
      };

      // Query US Census Geocoder (free, no API key required)
      try {
        const censusUrl = new URL("https://geocoding.geo.census.gov/geocoder/geographies/onelineaddress");
        censusUrl.searchParams.set("address", address);
        censusUrl.searchParams.set("benchmark", "Public_AR_Current");
        censusUrl.searchParams.set("vintage", "Current_Current");
        censusUrl.searchParams.set("format", "json");

        console.log(`[API v1 Address] Census request: ${censusUrl.toString()}`);
        const censusResponse = await fetch(censusUrl.toString());
        const censusData = await censusResponse.json();

        if (censusData.result?.addressMatches?.length > 0) {
          const match = censusData.result.addressMatches[0];
          const geographies = match.geographies;
          
          const stateFips = geographies?.States?.[0]?.STATE || null;
          const countyFips = geographies?.Counties?.[0]?.COUNTY || null;
          const tractCode = geographies?.["Census Tracts"]?.[0]?.TRACT || null;
          const tractGeoid = geographies?.["Census Tracts"]?.[0]?.GEOID || null;

          results.census = {
            matched: true,
            matchedAddress: match.matchedAddress,
            coordinates: {
              latitude: match.coordinates?.y,
              longitude: match.coordinates?.x,
            },
            county: geographies?.Counties?.[0]?.NAME || null,
            state: geographies?.States?.[0]?.NAME || null,
            tract: geographies?.["Census Tracts"]?.[0]?.NAME || null,
            tractGeoid: tractGeoid,
            blockGroup: geographies?.["Census Block Groups"]?.[0]?.NAME || null,
            stateFips,
            countyFips,
            tractCode,
          };

          // Fetch income data from Census ACS API
          if (stateFips && countyFips && tractCode) {
            try {
              const acsUrl = `https://api.census.gov/data/2022/acs/acs5?get=NAME,B19013_001E,B19019_001E,B19301_001E&for=tract:${tractCode}&in=state:${stateFips}&in=county:${countyFips}`;
              const acsResponse = await fetch(acsUrl);
              const acsData = await acsResponse.json();
              
              if (Array.isArray(acsData) && acsData.length > 1) {
                const [, values] = acsData;
                results.census.income = {
                  medianHouseholdIncome: values[1] ? parseInt(values[1]) : null,
                  medianFamilyIncome: values[2] ? parseInt(values[2]) : null,
                  perCapitaIncome: values[3] ? parseInt(values[3]) : null,
                  source: "American Community Survey 5-Year (2022)",
                };
              }
            } catch (acsError: any) {
              console.error("[API v1 Address] ACS API error:", acsError.message);
            }

            // Calculate LMI designation
            try {
              const stateAcsUrl = `https://api.census.gov/data/2022/acs/acs5?get=B19013_001E&for=state:${stateFips}`;
              const stateAcsResponse = await fetch(stateAcsUrl);
              const stateAcsData = await stateAcsResponse.json();
              
              if (Array.isArray(stateAcsData) && stateAcsData.length > 1 && results.census.income?.medianHouseholdIncome) {
                const stateMedianIncome = parseInt(stateAcsData[1][0]);
                const tractMedianIncome = results.census.income.medianHouseholdIncome;
                const incomeRatio = (tractMedianIncome / stateMedianIncome) * 100;
                
                let lmiDesignation: string;
                if (incomeRatio < 50) {
                  lmiDesignation = "Low";
                } else if (incomeRatio < 80) {
                  lmiDesignation = "Moderate";
                } else if (incomeRatio < 120) {
                  lmiDesignation = "Middle";
                } else {
                  lmiDesignation = "Upper";
                }
                
                results.census.lmi = {
                  designation: lmiDesignation,
                  tractMedianIncome,
                  stateMedianIncome,
                  incomeRatioPercent: Math.round(incomeRatio),
                  isLmiTract: incomeRatio < 80,
                  description: `Tract income is ${Math.round(incomeRatio)}% of state median`,
                };
              }
            } catch (lmiError: any) {
              console.error("[API v1 Address] LMI calculation error:", lmiError.message);
            }
          }
        } else {
          results.census = {
            matched: false,
            message: "No address match found",
          };
        }
      } catch (error: any) {
        console.error("[API v1 Address] Census API error:", error.message);
        results.census = {
          error: true,
          message: error.message,
        };
      }

      // Query Google Maps Geocoding API
      const googleApiKey = process.env.GOOGLE_MAPS_API_KEY;
      if (googleApiKey) {
        try {
          const googleUrl = new URL("https://maps.googleapis.com/maps/api/geocode/json");
          googleUrl.searchParams.set("address", address);
          googleUrl.searchParams.set("key", googleApiKey);

          console.log(`[API v1 Address] Google Maps request for: ${address}`);
          const googleResponse = await fetch(googleUrl.toString());
          const googleData = await googleResponse.json();

          if (googleData.status === "OK" && googleData.results?.length > 0) {
            const result = googleData.results[0];
            const location = result.geometry?.location;
            
            const getComponent = (type: string) => {
              const component = result.address_components?.find((c: any) => c.types?.includes(type));
              return component?.long_name || null;
            };
            
            const getShortComponent = (type: string) => {
              const component = result.address_components?.find((c: any) => c.types?.includes(type));
              return component?.short_name || null;
            };
            
            const getCityComponent = () => {
              const cityTypes = ["locality", "postal_town", "sublocality_level_1", "sublocality", "administrative_area_level_3"];
              for (const type of cityTypes) {
                const value = getComponent(type);
                if (value) return value;
              }
              return null;
            };

            results.google = {
              matched: true,
              formattedAddress: result.formatted_address,
              coordinates: {
                latitude: location?.lat,
                longitude: location?.lng,
              },
              streetNumber: getComponent("street_number"),
              route: getComponent("route"),
              subpremise: getComponent("subpremise"),
              city: getCityComponent(),
              county: getComponent("administrative_area_level_2"),
              state: getShortComponent("administrative_area_level_1"),
              stateFull: getComponent("administrative_area_level_1"),
              zipCode: getComponent("postal_code"),
              zipCodeSuffix: getComponent("postal_code_suffix"),
              country: getComponent("country"),
              placeId: result.place_id,
              raw: googleData,
            };
          } else {
            results.google = {
              matched: false,
              message: googleData.status === "ZERO_RESULTS" ? "No address match found" : googleData.status,
            };
          }
        } catch (error: any) {
          console.error("[API v1 Address] Google Maps API error:", error.message);
          results.google = {
            error: true,
            message: error.message,
          };
        }
      } else {
        results.google = {
          configured: false,
          message: "Google Maps API not configured",
        };
      }

      // Query USPS Address Validation API with credential rotation
      try {
        const credentials = await storage.getActiveUspsCredentials();
        
        if (credentials.length === 0) {
          results.usps = {
            configured: false,
            message: "No USPS credentials available",
          };
        } else {
          let uspsSuccess = false;
          let lastError = "";
          
          for (const cred of credentials) {
            try {
              console.log(`[API v1 Address] Trying USPS credential: ${cred.name || cred.id}`);
              
              const tokenResponse = await fetch("https://apis.usps.com/oauth2/v3/token", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  client_id: cred.clientId,
                  client_secret: cred.clientSecret,
                  grant_type: "client_credentials",
                }),
              });
              
              if (!tokenResponse.ok) {
                console.log(`[API v1 Address] USPS OAuth failed for ${cred.name || cred.id}`);
                lastError = `OAuth failed: ${tokenResponse.status}`;
                continue;
              }
              
              const tokenData = await tokenResponse.json();
              const accessToken = tokenData.access_token;
              
              if (!accessToken) {
                lastError = "No access token returned";
                continue;
              }
              
              // Parse address components
              let street = "";
              let city = "";
              let stateCode = "";
              let zipCode = "";
              
              if (results.google?.matched) {
                street = results.google.streetNumber 
                  ? `${results.google.streetNumber} ${results.google.route || ""}`
                  : results.google.route || "";
                city = results.google.city || "";
                stateCode = results.google.state || "";
                zipCode = results.google.zipCode || "";
              } else {
                const addressParts = address.split(",").map((p: string) => p.trim());
                street = addressParts[0] || "";
                if (addressParts.length >= 2) city = addressParts[1] || "";
                if (addressParts.length >= 3) {
                  const stateZip = addressParts[2].trim().split(" ");
                  stateCode = stateZip[0] || "";
                  zipCode = stateZip[1] || "";
                }
              }
              
              const uspsApiUrl = new URL("https://apis.usps.com/addresses/v3/address");
              uspsApiUrl.searchParams.set("streetAddress", street);
              if (city) uspsApiUrl.searchParams.set("city", city);
              if (stateCode) uspsApiUrl.searchParams.set("state", stateCode);
              if (zipCode) uspsApiUrl.searchParams.set("ZIPCode", zipCode);
              
              const uspsResponse = await fetch(uspsApiUrl.toString(), {
                headers: {
                  "Authorization": `Bearer ${accessToken}`,
                  "Accept": "application/json",
                },
              });
              
              await storage.updateUspsCredentialUsage(cred.id);
              
              if (!uspsResponse.ok) {
                if (uspsResponse.status === 429 || uspsResponse.status === 401 || uspsResponse.status === 403) {
                  lastError = `API error: ${uspsResponse.status}`;
                  continue;
                }
                results.usps = {
                  configured: true,
                  matched: false,
                  error: true,
                  message: `USPS API error: ${uspsResponse.status}`,
                };
                uspsSuccess = true;
                break;
              }
              
              const uspsData = await uspsResponse.json();
              const uspsAddress = uspsData.address || uspsData;
              
              if (uspsAddress.streetAddress || uspsAddress.city) {
                // Extract corrections from the raw response
                const corrections = uspsData.corrections || [];
                
                results.usps = {
                  configured: true,
                  matched: true,
                  address1: uspsAddress.secondaryAddress || "",
                  address2: uspsAddress.streetAddress || "",
                  city: uspsAddress.city || "",
                  state: uspsAddress.state || "",
                  zip5: uspsAddress.ZIPCode || "",
                  zip4: uspsAddress.ZIPPlus4 || "",
                  fullZip: uspsAddress.ZIPPlus4 
                    ? `${uspsAddress.ZIPCode}-${uspsAddress.ZIPPlus4}` 
                    : uspsAddress.ZIPCode || "",
                  deliveryPoint: uspsAddress.deliveryPoint || "",
                  carrierRoute: uspsAddress.carrierRoute || "",
                  dpvConfirmation: uspsAddress.DPVConfirmation || "",
                  residential: uspsAddress.business === "N" ? "Y" : (uspsAddress.business === "Y" ? "N" : ""),
                  corrections: corrections.map((c: any) => ({
                    code: c.code || "",
                    text: c.text || "",
                  })),
                };
              } else {
                results.usps = {
                  configured: true,
                  matched: false,
                  message: "No USPS match found",
                };
              }
              
              uspsSuccess = true;
              break;
              
            } catch (credError: any) {
              console.error(`[API v1 Address] USPS error with ${cred.name || cred.id}:`, credError.message);
              lastError = credError.message;
            }
          }
          
          if (!uspsSuccess) {
            results.usps = {
              configured: true,
              error: true,
              message: `All USPS credentials failed. Last error: ${lastError}`,
            };
          }
        }
      } catch (error: any) {
        console.error("[API v1 Address] USPS error:", error.message);
        results.usps = {
          configured: false,
          error: true,
          message: error.message,
        };
      }

      // Normalize the address using all geocoding results BEFORE saving
      const normalizedAddress = normalizeAddress({
        google: results.google ? {
          matched: results.google.matched,
          raw: results.google.raw,
          city: results.google.city,
          county: results.google.county,
          state: results.google.state,
          zipCode: results.google.zipCode,
          formattedAddress: results.google.formattedAddress,
          coordinates: results.google.coordinates,
        } : null,
        usps: results.usps ? {
          matched: results.usps.matched,
          city: results.usps.city,
          state: results.usps.state,
          zip5: results.usps.zip5,
          zip4: results.usps.zip4,
          address2: results.usps.address2,
          corrections: results.usps.corrections,
        } : null,
        census: results.census ? {
          matched: results.census.matched,
          matchedAddress: results.census.matchedAddress,
          county: results.census.county,
          state: results.census.state,
          coordinates: results.census.coordinates,
        } : null,
      });

      // Save geocoding results to database
      let savedId = null;
      try {
        const insertData: any = {
          inputAddress: address,
          censusMatched: results.census?.matched === true,
          censusMatchedAddress: results.census?.matchedAddress ?? null,
          censusLatitude: results.census?.coordinates?.latitude != null ? String(results.census.coordinates.latitude) : null,
          censusLongitude: results.census?.coordinates?.longitude != null ? String(results.census.coordinates.longitude) : null,
          censusCounty: results.census?.county ?? null,
          censusState: results.census?.state ?? null,
          censusTract: results.census?.tract ?? null,
          censusTractGeoid: results.census?.tractGeoid ?? null,
          censusBlockGroup: results.census?.blockGroup ?? null,
          censusStateFips: results.census?.stateFips ?? null,
          censusCountyFips: results.census?.countyFips ?? null,
          censusTractCode: results.census?.tractCode ?? null,
          googleMatched: results.google?.matched === true,
          googleFormattedAddress: results.google?.formattedAddress ?? null,
          googleLatitude: results.google?.coordinates?.latitude != null ? String(results.google.coordinates.latitude) : null,
          googleLongitude: results.google?.coordinates?.longitude != null ? String(results.google.coordinates.longitude) : null,
          googleCounty: results.google?.county ?? null,
          googleState: results.google?.stateFull ?? null,
          googleCity: results.google?.city ?? null,
          googleZipCode: results.google?.zipCode ?? null,
          googlePlaceId: results.google?.placeId ?? null,
          medianHouseholdIncome: results.census?.income?.medianHouseholdIncome != null ? Number(results.census.income.medianHouseholdIncome) : null,
          medianFamilyIncome: results.census?.income?.medianFamilyIncome != null ? Number(results.census.income.medianFamilyIncome) : null,
          perCapitaIncome: results.census?.income?.perCapitaIncome != null ? Number(results.census.income.perCapitaIncome) : null,
          incomeSource: results.census?.income?.source ?? null,
          lmiDesignation: results.census?.lmi?.designation ?? null,
          lmiTractMedianIncome: results.census?.lmi?.tractMedianIncome != null ? Number(results.census.lmi.tractMedianIncome) : null,
          lmiStateMedianIncome: results.census?.lmi?.stateMedianIncome != null ? Number(results.census.lmi.stateMedianIncome) : null,
          lmiIncomeRatioPercent: results.census?.lmi?.incomeRatioPercent != null ? Number(results.census.lmi.incomeRatioPercent) : null,
          isLmiTract: results.census?.lmi?.isLmiTract === true,
          uspsMatched: results.usps?.matched === true,
          uspsAddress1: results.usps?.address1 ?? null,
          uspsAddress2: results.usps?.address2 ?? null,
          uspsCity: results.usps?.city ?? null,
          uspsState: results.usps?.state ?? null,
          uspsZip5: results.usps?.zip5 ?? null,
          uspsZip4: results.usps?.zip4 ?? null,
          uspsDeliveryPoint: results.usps?.deliveryPoint ?? null,
          uspsCarrierRoute: results.usps?.carrierRoute ?? null,
          uspsDpvConfirmation: results.usps?.dpvConfirmation ?? null,
          uspsResidentialIndicator: results.usps?.residential ?? null,
          uspsError: results.usps?.error ? results.usps.message : null,
          source: "api",
          normalizedAddress: normalizedAddress,
        };
        
        const savedAddress = await storage.createGeocodedAddress(insertData);
        savedId = savedAddress.id;
        console.log(`[API v1 Address] Saved address lookup: ${savedId}`);
      } catch (saveError: any) {
        console.error("[API v1 Address] Failed to save address:", saveError.message);
      }

      const responseData = { ...normalizedAddress, savedId };
      
      // Log response before sending
      console.log("================================================================================");
      console.log("[API v1 Address] RESPONSE");
      console.log(`[API v1 Address] Status: 200`);
      console.log(`[API v1 Address] Duration: ${Date.now() - startTime}ms`);
      console.log(`[API v1 Address] Response Body:`, JSON.stringify(responseData, null, 2));
      console.log("================================================================================");
      
      await storage.createApiRequestLog({
        clientId: client.id,
        endpoint: "/api/v1/address",
        method: "POST",
        statusCode: 200,
        durationMs: Date.now() - startTime,
        requestBody: maskSensitiveData(req.body),
        responseBody: { success: true, savedId },
        ipAddress: req.ip || req.socket.remoteAddress,
      });

      return res.json(responseData);
    } catch (error: any) {
      console.error("[API v1 Address] Request failed:", error.message);
      await storage.createApiRequestLog({
        clientId: client.id,
        endpoint: "/api/v1/address",
        method: "POST",
        statusCode: 500,
        durationMs: Date.now() - startTime,
        requestBody: maskSensitiveData(req.body),
        errorMessage: error.message,
        ipAddress: req.ip || req.socket.remoteAddress,
      });
      return res.status(500).json({ error: error.message });
    }
  });

  // Admin: API Client Management
  app.get("/api/admin/clients", async (req, res) => {
    try {
      const clients = await storage.getAllApiClients();
      const clientsData = clients.map(c => ({
        id: c.id,
        name: c.name,
        clientId: c.clientId,
        clientSecret: c.clientSecret,
        isEnabled: c.isEnabled,
        lastUsedAt: c.lastUsedAt,
        createdAt: c.createdAt,
      }));
      return res.json(clientsData);
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/admin/clients", async (req, res) => {
    try {
      const { name } = req.body;
      if (!name || typeof name !== "string") {
        return res.status(400).json({ error: "Client name is required" });
      }

      const { clientId, clientSecret } = generateClientCredentials();
      const clientSecretHash = hashSecret(clientSecret);

      const client = await storage.createApiClient({
        name,
        clientId,
        clientSecret,
        clientSecretHash,
        isEnabled: true,
      });

      return res.json({
        id: client.id,
        name: client.name,
        clientId: client.clientId,
        clientSecret, // Show only once!
        isEnabled: client.isEnabled,
        createdAt: client.createdAt,
      });
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.patch("/api/admin/clients/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { isEnabled, name } = req.body;

      const updates: any = {};
      if (typeof isEnabled === "boolean") updates.isEnabled = isEnabled;
      if (typeof name === "string") updates.name = name;

      const client = await storage.updateApiClient(id, updates);
      if (!client) {
        return res.status(404).json({ error: "Client not found" });
      }

      return res.json({
        id: client.id,
        name: client.name,
        clientId: client.clientId,
        isEnabled: client.isEnabled,
        lastUsedAt: client.lastUsedAt,
        createdAt: client.createdAt,
      });
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/admin/clients/:id/rotate-secret", async (req, res) => {
    try {
      const { id } = req.params;
      
      const existing = await storage.getApiClientById(id);
      if (!existing) {
        return res.status(404).json({ error: "Client not found" });
      }

      await storage.revokeApiTokensByClientId(id);

      const clientSecret = `sec_${crypto.randomBytes(32).toString("hex")}`;
      const clientSecretHash = hashSecret(clientSecret);

      await storage.updateApiClient(id, { clientSecret, clientSecretHash });

      return res.json({
        id: existing.id,
        name: existing.name,
        clientId: existing.clientId,
        clientSecret, // Show only once!
        message: "Secret rotated. All existing tokens have been revoked.",
      });
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.delete("/api/admin/clients/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteApiClient(id);
      return res.json({ success: true });
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/admin/request-logs", async (req, res) => {
    try {
      // Disable caching so logs always refresh
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
      
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;
      const logs = await storage.getApiRequestLogs(limit, offset);
      return res.json(logs);
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.delete("/api/admin/request-logs", async (req, res) => {
    try {
      await storage.clearApiRequestLogs();
      return res.json({ success: true });
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });
  
  app.get("/api/equifax/status", async (req, res) => {
    const configured = equifaxClient.isConfigured();
    const prescreenConfigured = equifaxClient.isPrescreenConfigured();
    const pqoConfigured = equifaxClient.isPQOConfigured();
    const missingConfig = configured ? [] : equifaxClient.getMissingConfig();
    const missingPqoConfig = pqoConfigured ? [] : equifaxClient.getMissingPQOConfig();
    const activeEnv = equifaxClient.getActiveEnvironment();
    
    return res.json({
      configured,
      prescreenConfigured,
      pqoConfigured,
      missingConfig,
      missingPqoConfig,
      environment: activeEnv,
      baseUrl: equifaxClient.getBaseUrl(),
    });
  });

  app.get("/api/equifax/request-logs", async (req, res) => {
    const logs = equifaxClient.getRequestLogs();
    return res.json(logs);
  });

  app.delete("/api/equifax/request-logs", async (req, res) => {
    equifaxClient.clearRequestLogs();
    return res.json({ success: true });
  });

  app.get("/api/equifax/environments", async (req, res) => {
    const environments = equifaxClient.getAllEnvironments();
    const active = equifaxClient.getActiveEnvironment();
    return res.json({ environments, active });
  });

  app.post("/api/equifax/environment", async (req, res) => {
    const { environment, confirmProduction } = req.body;
    
    if (!["sandbox", "test", "production"].includes(environment)) {
      return res.status(400).json({ error: "Invalid environment. Must be sandbox, test, or production." });
    }


    const envConfigs = equifaxClient.getAllEnvironments();
    const targetEnv = envConfigs.find(e => e.name === environment);
    
    if (!targetEnv?.configured) {
      return res.status(400).json({ 
        error: `Environment ${environment} is not fully configured. Missing: ${targetEnv?.missingSecrets.join(", ")}`,
        missingSecrets: targetEnv?.missingSecrets
      });
    }

    equifaxClient.setActiveEnvironment(environment as EquifaxEnvironment);
    
    console.log(`[Equifax] Environment switched to ${environment} at ${new Date().toISOString()}`);
    
    return res.json({ 
      success: true, 
      active: environment,
      baseUrl: targetEnv.baseUrl
    });
  });

  app.post("/api/equifax/refresh-token", async (req, res) => {
    try {
      const result = await equifaxClient.refreshToken();
      console.log(`[Equifax] Token refreshed for ${result.environment}: ${result.token} (expires in ${result.expiresIn}s)`);
      return res.json({
        success: true,
        environment: result.environment,
        token: result.token,
        expiresIn: result.expiresIn,
      });
    } catch (error: any) {
      console.error("[Equifax] Token refresh failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/equifax/refetch", async (req, res) => {
    try {
      const { path } = req.query;
      if (!path || typeof path !== "string") {
        return res.status(400).json({ error: "Missing report path parameter" });
      }
      
      console.log(`[Equifax] Re-fetching report from path: ${path}`);
      const report = await equifaxClient.refetchReportByPath(path);
      
      return res.json({
        success: true,
        consumer: report.consumer,
        scores: report.scores,
        tradelines: report.tradelines,
        inquiries: report.inquiries,
        pdfPath: report.pdfPath,
        rawEquifaxResponse: report.rawEquifaxResponse,
        refetchedAt: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error("[Equifax] Re-fetch failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/equifax/pdf", async (req, res) => {
    try {
      const { path } = req.query;
      if (!path || typeof path !== "string") {
        return res.status(400).json({ error: "Missing PDF path parameter" });
      }
      
      console.log(`[Equifax] Fetching PDF from path: ${path}`);
      const pdfBuffer = await equifaxClient.fetchPdf(path);
      
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "inline; filename=credit-report.pdf");
      return res.send(pdfBuffer);
    } catch (error: any) {
      console.error("[Equifax] PDF fetch failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/reports/:consumerId/styled-pdf", async (req, res) => {
    try {
      const { consumerId } = req.params;
      
      if (!consumerId) {
        return res.status(400).json({ error: "Missing consumer ID" });
      }
      
      const consumer = await storage.getConsumerById(consumerId);
      if (!consumer) {
        return res.status(404).json({ error: "Consumer not found" });
      }
      
      console.log(`[PDF] Generating styled PDF for consumer ${consumerId}`);
      
      const { chromium } = await import("playwright");
      const browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      try {
        const page = await browser.newPage();
        
        const baseUrl = `http://localhost:${process.env.PORT || 5000}`;
        const printUrl = `${baseUrl}/print-report/${consumerId}`;
        
        console.log(`[PDF] Loading print page: ${printUrl}`);
        await page.goto(printUrl, { waitUntil: 'networkidle', timeout: 30000 });
        
        await page.waitForFunction(() => (window as any).__reportReady === true, { timeout: 15000 });
        
        const hasError = await page.$('[data-error="true"]');
        if (hasError) {
          throw new Error("Report data not available for this consumer");
        }
        
        await page.waitForTimeout(500);
        
        const pdfBuffer = await page.pdf({
          format: 'Letter',
          margin: { top: '0.5in', right: '0.5in', bottom: '0.5in', left: '0.5in' },
          printBackground: true,
        });
        
        const consumerName = `${consumer.firstName || ''}_${consumer.lastName || ''}`.replace(/[^a-zA-Z0-9]/g, '_');
        const filename = `HerringBank_CreditReport_${consumerName}.pdf`;
        
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.setHeader("Content-Length", pdfBuffer.length);
        
        console.log(`[PDF] Successfully generated styled PDF (${pdfBuffer.length} bytes)`);
        return res.send(pdfBuffer);
        
      } finally {
        await browser.close();
      }
      
    } catch (error: any) {
      console.error("[PDF] Styled PDF generation failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/consumers", async (req, res) => {
    try {
      const consumers = await storage.getAllConsumers();
      const consumersWithScores = await Promise.all(
        consumers.map(async (consumer) => {
          const scores = await storage.getScoresByConsumerId(consumer.id);
          const tradelines = await storage.getTradelinesByConsumerId(consumer.id);
          const inquiries = await storage.getInquiriesByConsumerId(consumer.id);
          const queryName = consumer.requestFirstName || consumer.requestLastName
            ? `${consumer.requestFirstName || ""} ${consumer.requestLastName || ""}`.trim()
            : null;
          const equifaxName = `${consumer.firstName} ${consumer.lastName}`.trim();
          return {
            id: consumer.id,
            name: queryName || equifaxName,
            equifaxName: equifaxName !== queryName ? equifaxName : null,
            ssn: consumer.ssn,
            dateOfBirth: consumer.dateOfBirth,
            primaryScore: scores[0]?.score || null,
            scoreRating: scores[0]?.rating || null,
            tradelineCount: tradelines.length,
            inquiryCount: inquiries.length,
            hitCodeDescription: consumer.hitCodeDescription,
            environment: consumer.environment,
            pdfStoragePath: consumer.pdfStoragePath,
            pdfImageStoragePath: consumer.pdfImageStoragePath,
            reportDate: consumer.reportDate,
            source: consumer.source || "browser",
            createdAt: consumer.createdAt,
          };
        })
      );
      return res.json(consumersWithScores);
    } catch (error) {
      console.error("Error fetching consumers:", error);
      return res.status(500).json({ error: "Failed to fetch consumers" });
    }
  });

  app.delete("/api/consumers/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteConsumer(id);
      console.log(`[API] Deleted consumer ${id}`);
      return res.json({ success: true });
    } catch (error) {
      console.error("Error deleting consumer:", error);
      return res.status(500).json({ error: "Failed to delete consumer" });
    }
  });

  app.get("/api/reports/:id/experian", async (req, res) => {
    try {
      const { id } = req.params;
      const report = await storage.getFullCreditReportById(id);
      
      if (!report) {
        return res.status(404).json({ error: "Credit report not found" });
      }
      
      const allScoreFactors = report.scores.flatMap(s => s.factors);
      
      const experianReport = transformToExperianFormat(
        report.consumer,
        report.addresses,
        report.scores,
        allScoreFactors,
        report.tradelines,
        report.inquiries,
        report.fraudAlerts,
        report.ofacAlerts
      );
      
      console.log(`[API] Generated Experian format report for consumer ${id}`);
      return res.json(experianReport);
    } catch (error: any) {
      console.error("Error generating Experian report:", error);
      return res.status(500).json({ error: error.message || "Failed to generate Experian report" });
    }
  });

  app.patch("/api/consumers/:id/query", async (req, res) => {
    try {
      const { id } = req.params;
      const { firstName, lastName, middleName, ssn, dateOfBirth, address } = req.body;
      
      const consumer = await storage.getConsumerById(id);
      if (!consumer) {
        return res.status(404).json({ error: "Consumer not found" });
      }
      
      const updatedConsumer = await storage.updateConsumer(id, {
        requestFirstName: firstName ?? consumer.requestFirstName,
        requestLastName: lastName ?? consumer.requestLastName,
        requestMiddleName: middleName ?? consumer.requestMiddleName,
        requestSsn: ssn ?? consumer.requestSsn,
        requestDateOfBirth: dateOfBirth ?? consumer.requestDateOfBirth,
        requestStreet: address?.street ?? consumer.requestStreet,
        requestCity: address?.city ?? consumer.requestCity,
        requestState: address?.state ?? consumer.requestState,
        requestZip: address?.zipCode ?? consumer.requestZip,
      });
      
      console.log(`[API] Updated query data for consumer ${id}`);
      return res.json({ success: true, consumer: updatedConsumer });
    } catch (error) {
      console.error("Error updating consumer query data:", error);
      return res.status(500).json({ error: "Failed to update query data" });
    }
  });

  app.post("/api/consumers/:id/reparse", async (req, res) => {
    try {
      const { id } = req.params;
      const consumer = await storage.getConsumerById(id);
      
      if (!consumer) {
        return res.status(404).json({ error: "Consumer not found" });
      }
      
      if (!consumer.rawEquifaxResponse) {
        return res.status(400).json({ error: "No raw Equifax response stored for this consumer" });
      }
      
      console.log(`[API] Reparsing credit report for consumer ${id}`);
      
      // Delete ALL existing parsed data including new tables
      await Promise.all([
        storage.deleteAddressesByConsumerId(id),
        storage.deleteScoresByConsumerId(id),
        storage.deleteTradelinesByConsumerId(id),
        storage.deleteInquiriesByConsumerId(id),
        storage.deleteFraudAlertsByConsumerId(id),
        storage.deleteOfacAlertsByConsumerId(id),
        storage.deleteDataxTransactionByConsumerId(id),
        storage.deleteDataxIndicatorsByConsumerId(id),
        storage.deleteDataxSummaryByConsumerId(id),
      ]);
      
      // Re-normalize the raw response with full extraction
      const normalized = equifaxClient.normalizeReport(consumer.rawEquifaxResponse, consumer.ssn);
      
      // Update consumer with expanded metadata
      await storage.updateConsumer(id, {
        firstName: normalized.consumer.firstName || undefined,
        lastName: normalized.consumer.lastName || undefined,
        middleName: normalized.consumer.middleName || undefined,
        dateOfBirth: normalized.consumer.dateOfBirth || undefined,
        reportDate: normalized.consumer.reportDate || undefined,
        fileSinceDate: normalized.consumer.fileSinceDate || undefined,
        lastActivityDate: normalized.consumer.lastActivityDate || undefined,
        hitCode: normalized.consumer.hitCode || undefined,
        hitCodeDescription: normalized.consumer.hitCodeDescription || undefined,
        customerNumber: normalized.consumer.customerNumber || undefined,
        ecoaInquiryType: normalized.consumer.ecoaInquiryType || undefined,
      });
      
      // Save ALL addresses with full details
      for (const addr of normalized.addresses || []) {
        await storage.createAddress({
          consumerId: id,
          addressType: addr.identifier || "current",
          houseNumber: addr.houseNumber || undefined,
          streetName: addr.streetName || undefined,
          streetType: addr.streetType || undefined,
          apartmentNumber: addr.apartmentNumber || undefined,
          cityName: addr.cityName || undefined,
          stateAbbreviation: addr.stateAbbreviation || undefined,
          zipCode: addr.zipCode || undefined,
          rentOwnBuy: addr.rentOwnBuy || undefined,
          sourceOfAddressDescription: addr.sourceOfAddressDescription || undefined,
          dateFirstReported: addr.dateFirstReported || undefined,
          dateLastReported: addr.dateLastReported || undefined,
        });
      }
      
      // Fallback: if no addresses, parse from string
      if ((!normalized.addresses || normalized.addresses.length === 0) && normalized.consumer.address) {
        const addressParts = normalized.consumer.address.split(", ");
        if (addressParts.length >= 3) {
          const stateZip = addressParts[2].split(" ");
          await storage.createAddress({
            consumerId: id,
            addressType: "current",
            addressLine1: addressParts[0],
            cityName: addressParts[1],
            stateAbbreviation: stateZip[0],
            zipCode: stateZip[1],
          });
        }
      }
      
      // Save scores with ALL fields
      for (const score of normalized.scores) {
        const savedScore = await storage.createCreditScore({
          consumerId: id,
          modelIdentifier: score.model,
          modelName: score.model,
          modelType: score.modelType || undefined,
          score: score.value,
          minScore: score.minScore || undefined,
          maxScore: score.maxScore || 850,
          riskBasedPricingLowRange: score.riskBasedPricingLowRange || undefined,
          riskBasedPricingHighRange: score.riskBasedPricingHighRange || undefined,
          riskBasedPricingPercentage: score.riskBasedPricingPercentage || undefined,
          rating: getScoreRating(score.value),
        });
        
        for (const factor of score.factors || []) {
          await storage.createScoreFactor({
            scoreId: savedScore.id,
            factorCode: factor.code,
            factorDescription: factor.description,
            rank: factor.rank || 1,
          });
        }
      }
      
      // Save tradelines with ALL fields including narratives and payment history
      for (const tl of normalized.tradelines) {
        const savedTl = await storage.createTradeline({
          consumerId: id,
          customerNumber: tl.customerNumber || undefined,
          subscriberName: tl.creditorName,
          accountNumber: tl.accountNumber || undefined,
          accountTypeCode: tl.accountTypeCode || undefined,
          accountType: tl.accountType || undefined,
          accountDesignatorCode: tl.accountDesignatorCode || undefined,
          accountDesignatorDescription: tl.accountDesignatorDescription || undefined,
          portfolioTypeCode: tl.portfolioTypeCode || undefined,
          portfolioTypeDescription: tl.portfolioTypeDescription || undefined,
          activityDesignatorCode: tl.activityDesignatorCode || undefined,
          activityDesignatorDescription: tl.activityDesignatorDescription || undefined,
          currentBalance: tl.currentBalance,
          highCredit: tl.highCredit || undefined,
          creditLimit: tl.creditLimit || undefined,
          paymentAmount: tl.paymentAmount || undefined,
          actualPaymentAmount: tl.actualPaymentAmount || undefined,
          scheduledPaymentAmount: tl.scheduledPaymentAmount || undefined,
          pastDueAmount: tl.pastDueAmount || undefined,
          dateOpened: tl.dateOpened || undefined,
          dateClosed: tl.dateClosed || undefined,
          dateReported: tl.dateReported || undefined,
          dateLastPayment: tl.dateLastPayment || undefined,
          dateLastActivity: tl.dateLastActivity || undefined,
          dateMajorDelinquencyFirstReported: tl.dateMajorDelinquencyFirstReported || undefined,
          monthsReviewed: tl.monthsReviewed || undefined,
          thirtyDayCounter: tl.thirtyDayCounter || undefined,
          sixtyDayCounter: tl.sixtyDayCounter || undefined,
          ninetyDayCounter: tl.ninetyDayCounter || undefined,
          accountStatusCode: tl.accountStatusCode || undefined,
          accountStatusDescription: tl.accountStatus || undefined,
          rateCode: tl.rateCode || undefined,
          rateDescription: tl.rateDescription || undefined,
          termsFrequencyCode: tl.termsFrequencyCode || undefined,
          termsFrequencyDescription: tl.termsFrequencyDescription || undefined,
          termsDurationCode: tl.termsDurationCode || undefined,
          termsDurationDescription: tl.termsDurationDescription || undefined,
          previousHighRate1: tl.previousHighRate1 || undefined,
          previousHighDate1: tl.previousHighDate1 || undefined,
          previousHighRate2: tl.previousHighRate2 || undefined,
          previousHighDate2: tl.previousHighDate2 || undefined,
          previousHighRate3: tl.previousHighRate3 || undefined,
          previousHighDate3: tl.previousHighDate3 || undefined,
          automatedUpdateIndicator: tl.automatedUpdateIndicator || undefined,
          paymentHistory24: tl.paymentHistory24 || undefined,
        });
        
        // Save narrative codes
        for (const nc of tl.narrativeCodes || []) {
          await storage.createTradelineNarrative({
            tradelineId: savedTl.id,
            narrativeCode: nc.code,
            narrativeDescription: nc.description || undefined,
          });
        }
        
        // Save payment history
        for (const ph of tl.paymentHistory || []) {
          await storage.createTradelinePaymentHistory({
            tradelineId: savedTl.id,
            monthIndex: ph.monthIndex,
            statusCode: ph.statusCode || undefined,
            statusDescription: ph.statusDescription || undefined,
          });
        }
      }
      
      // Save inquiries with ALL fields
      for (const inq of normalized.inquiries) {
        await storage.createInquiry({
          consumerId: id,
          inquiryType: inq.inquiryType || undefined,
          inquiryDate: inq.date,
          customerNumber: inq.customerNumber || undefined,
          customerName: inq.subscriber,
          industryCode: inq.industryCode || undefined,
          industryDescription: inq.industryDescription || undefined,
        });
      }
      
      // Save fraud alerts
      for (const alert of normalized.fraudAlerts || []) {
        await storage.createFraudAlert({
          consumerId: id,
          alertTypeCode: alert.alertTypeCode || undefined,
          alertTypeDescription: alert.alertTypeDescription || undefined,
          dateReported: alert.dateReported || undefined,
          effectiveDate: alert.effectiveDate || undefined,
          contactPhones: alert.contactPhones || undefined,
        });
      }
      
      // Save OFAC alerts
      for (const ofac of normalized.ofacAlerts || []) {
        await storage.createOfacAlert({
          consumerId: id,
          memberFirmCode: ofac.memberFirmCode || undefined,
          cdcResponseCode: ofac.cdcResponseCode || undefined,
          transactionType: ofac.transactionType || undefined,
          cdcTransactionDate: ofac.cdcTransactionDate || undefined,
          cdcTransactionTime: ofac.cdcTransactionTime || undefined,
          legalVerbiage: ofac.legalVerbiage || undefined,
          dataSegmentRegulated: ofac.dataSegmentRegulated || undefined,
          revisedLegalVerbiageIndicator: ofac.revisedLegalVerbiageIndicator || undefined,
        });
      }
      
      // Save DataX transaction
      if (normalized.dataxTransaction) {
        await storage.createDataxTransaction({
          consumerId: id,
          trackId: normalized.dataxTransaction.trackId || undefined,
          trackHash: normalized.dataxTransaction.trackHash || undefined,
          transactionId: normalized.dataxTransaction.transactionId || undefined,
          codeVersion: normalized.dataxTransaction.codeVersion || undefined,
          requestVersion: normalized.dataxTransaction.requestVersion || undefined,
          generationTime: normalized.dataxTransaction.generationTime || undefined,
          globalDecisionResult: normalized.dataxTransaction.globalDecisionResult || undefined,
          craBucket: normalized.dataxTransaction.craBucket || undefined,
        });
      }
      
      // Save DataX indicators
      for (const ind of normalized.dataxIndicators || []) {
        await storage.createDataxIndicator({
          consumerId: id,
          indicatorCode: ind.indicatorCode,
          indicatorCount: ind.indicatorCount || undefined,
          indicatorMessage: ind.indicatorMessage || undefined,
        });
      }
      
      // Save DataX summary
      if (normalized.dataxSummary) {
        await storage.createDataxSummary({
          consumerId: id,
          totalTradelines: normalized.dataxSummary.totalTradelines || undefined,
          currentTradelines: normalized.dataxSummary.currentTradelines || undefined,
          totalChargeOffs: normalized.dataxSummary.totalChargeOffs || undefined,
          totalRecoveries: normalized.dataxSummary.totalRecoveries || undefined,
          totalPaidOffs: normalized.dataxSummary.totalPaidOffs || undefined,
          firstPaymentDefaults: normalized.dataxSummary.firstPaymentDefaults || undefined,
          firstPaymentFatals: normalized.dataxSummary.firstPaymentFatals || undefined,
          daysSinceLastAch: normalized.dataxSummary.daysSinceLastAch || undefined,
          daysSinceLastReturn: normalized.dataxSummary.daysSinceLastReturn || undefined,
          daysSinceLastTradeline: normalized.dataxSummary.daysSinceLastTradeline || undefined,
          daysSinceLastFatalReturn: normalized.dataxSummary.daysSinceLastFatalReturn || undefined,
          lastPaymentDate: normalized.dataxSummary.lastPaymentDate || undefined,
          lastPaymentAmount: normalized.dataxSummary.lastPaymentAmount || undefined,
          lastPaymentType: normalized.dataxSummary.lastPaymentType || undefined,
          lastPaymentDisposition: normalized.dataxSummary.lastPaymentDisposition || undefined,
          lastReturnDate: normalized.dataxSummary.lastReturnDate || undefined,
          lastReturnReason: normalized.dataxSummary.lastReturnReason || undefined,
          lastReturnMessage: normalized.dataxSummary.lastReturnMessage || undefined,
          lastInquiryDate: normalized.dataxSummary.lastInquiryDate || undefined,
          lastTradelineDate: normalized.dataxSummary.lastTradelineDate || undefined,
          lastChargeOffDate: normalized.dataxSummary.lastChargeOffDate || undefined,
          lastThreePayments: normalized.dataxSummary.lastThreePayments || undefined,
          maximumOpenTradelines: normalized.dataxSummary.maximumOpenTradelines || undefined,
          maximumTotalPrincipal: normalized.dataxSummary.maximumTotalPrincipal || undefined,
          maximumTradelinePrincipal: normalized.dataxSummary.maximumTradelinePrincipal || undefined,
          totalCurrentPrincipal: normalized.dataxSummary.totalCurrentPrincipal || undefined,
          totalAchDebitAttempts: normalized.dataxSummary.totalAchDebitAttempts || undefined,
          totalUniqueMemberTradelines: normalized.dataxSummary.totalUniqueMemberTradelines || undefined,
          tradelinesByInquiringMember: normalized.dataxSummary.tradelinesByInquiringMember || undefined,
          addressDiscrepancyIndicator: normalized.dataxSummary.addressDiscrepancyIndicator || undefined,
          rawSummaryData: normalized.dataxSummary.rawSummaryData || undefined,
        });
      }
      
      console.log(`[API] Reparsed credit report for consumer ${id}: ` +
        `${normalized.scores.length} scores, ${normalized.tradelines.length} tradelines, ` +
        `${normalized.inquiries.length} inquiries, ${normalized.addresses?.length || 0} addresses, ` +
        `${normalized.fraudAlerts?.length || 0} fraud alerts, ${normalized.ofacAlerts?.length || 0} OFAC alerts, ` +
        `DataX: ${normalized.dataxTransaction ? 'yes' : 'no'}, ${normalized.dataxIndicators?.length || 0} indicators`);
      
      return res.json({
        success: true,
        message: "Credit report reparsed successfully with full data extraction",
        summary: {
          scores: normalized.scores.length,
          tradelines: normalized.tradelines.length,
          inquiries: normalized.inquiries.length,
          addresses: normalized.addresses?.length || 0,
          fraudAlerts: normalized.fraudAlerts?.length || 0,
          ofacAlerts: normalized.ofacAlerts?.length || 0,
          hasDataxTransaction: !!normalized.dataxTransaction,
          dataxIndicators: normalized.dataxIndicators?.length || 0,
          hasDataxSummary: !!normalized.dataxSummary,
        },
      });
    } catch (error) {
      console.error("Error reparsing credit report:", error);
      return res.status(500).json({ error: "Failed to reparse credit report" });
    }
  });

  app.get("/api/reports/:ssn", async (req, res) => {
    try {
      const { ssn } = req.params;
      const fullReport = await storage.getFullCreditReport(ssn);
      
      if (!fullReport) {
        return res.status(404).json({ 
          error: "Credit report not found for this SSN" 
        });
      }
      
      return res.json({
        ...formatFullReportForApi(fullReport),
        source: "cache",
        cachedAt: fullReport.consumer.updatedAt,
      });
    } catch (error) {
      console.error("Error fetching cached credit report:", error);
      return res.status(500).json({ 
        error: "Failed to fetch credit report" 
      });
    }
  });

  app.get("/api/reports/id/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const fullReport = await storage.getFullCreditReportById(id);
      
      if (!fullReport) {
        return res.status(404).json({ 
          error: "Credit report not found for this customer ID" 
        });
      }
      
      const formattedReport = formatFullReportForApi(fullReport);
      console.log(`[API] Report ID ${id} - rawEquifaxResponse present:`, !!formattedReport.rawEquifaxResponse);
      console.log(`[API] Report ID ${id} - links:`, (formattedReport.rawEquifaxResponse as any)?.links);
      
      return res.json({
        ...formattedReport,
        source: "cache",
        cachedAt: fullReport.consumer.updatedAt,
      });
    } catch (error) {
      console.error("Error fetching cached credit report by ID:", error);
      return res.status(500).json({ 
        error: "Failed to fetch credit report" 
      });
    }
  });

  app.post("/api/equifax/credit-report", async (req, res) => {
    try {
      if (!equifaxClient.isConfigured()) {
        const missing = equifaxClient.getMissingConfig();
        return res.status(503).json({
          error: "Equifax API is not fully configured",
          missingSecrets: missing,
          message: `Please add the following secrets: ${missing.join(", ")}`,
        });
      }

      const validationResult = creditReportRequestSchema.safeParse(req.body);
      if (!validationResult.success) {
        const validationError = fromError(validationResult.error);
        const maskedRequest = {
          ...req.body,
          ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
        };
        return res.status(400).json({ 
          error: validationError.toString(),
          originalRequest: maskedRequest,
        });
      }

      const request = validationResult.data;
      
      console.log(`[API] Pulling credit report for ${request.firstName} ${request.lastName}`);
      const equifaxReport = await equifaxClient.getCreditReport(request);
      
      console.log(`[API] Environment: ${equifaxClient.getActiveEnvironment()}, pdfPath: ${equifaxReport.pdfPath || 'NONE'}, storage configured: ${objectStorageService.isConfigured()}`);
      
      // Save to normalized tables with raw response for reparsing
      const savedReport = await saveNormalizedReport(equifaxReport, request.ssn || "", equifaxReport.rawEquifaxResponse, {
        firstName: request.firstName,
        lastName: request.lastName,
        middleName: request.middleName,
        ssn: request.ssn,
        dateOfBirth: request.dateOfBirth,
        street: request.address?.street,
        city: request.address?.city,
        state: request.address?.state,
        zip: request.address?.zipCode,
        source: "browser",
      });
      
      // Auto-upload PDF to Replit Object Storage whenever Equifax provides a link
      let storageUploadResult = null;
      const activeEnv = equifaxClient.getActiveEnvironment();
      if (equifaxReport.pdfPath && objectStorageService.isConfigured()) {
        try {
          console.log(`[ObjectStorage] Auto-uploading PDF for ${activeEnv} report from: ${equifaxReport.pdfPath}`);
          const pdfBuffer = await equifaxClient.fetchPdf(equifaxReport.pdfPath);
          const consumerName = `${request.firstName} ${request.lastName}`;
          storageUploadResult = await objectStorageService.uploadPdf(
            pdfBuffer,
            consumerName,
            request.ssn || "",
            activeEnv
          );
          console.log(`[ObjectStorage] Upload result:`, storageUploadResult);
          
          // Save PDF path to consumer record
          if (storageUploadResult.success && storageUploadResult.objectPath) {
            await storage.updateConsumer(savedReport.consumer.id, {
              pdfStoragePath: storageUploadResult.objectPath,
            });
            
            // Convert PDF to images and save to storage for persistent inline display
            try {
              console.log(`[ObjectStorage] Converting PDF to images for permanent storage...`);
              const { convertPdfToImages } = await import("./pdfConverter");
              const pages = await convertPdfToImages(pdfBuffer, 1.5);
              
              if (pages.length > 0) {
                const consumerName = `${request.firstName} ${request.lastName}`;
                const imagesResult = await objectStorageService.uploadPdfImages(
                  pages,
                  consumerName,
                  savedReport.consumer.id,
                  request.ssn || "",
                  activeEnv
                );
                
                if (imagesResult.success && imagesResult.objectPath) {
                  await storage.updateConsumer(savedReport.consumer.id, {
                    pdfImageStoragePath: imagesResult.objectPath,
                  });
                  console.log(`[ObjectStorage] PDF images saved: ${imagesResult.objectPath}`);
                }
              }
            } catch (imageError: any) {
              console.error(`[ObjectStorage] PDF image conversion failed:`, imageError.message);
              // Non-fatal - PDF is still available
            }
          }
        } catch (pdfError: any) {
          // Note: Equifax sandbox returns 406 for PDF requests - this is a known limitation
          if (pdfError.message?.includes("406") && activeEnv === "sandbox") {
            console.log(`[ObjectStorage] Sandbox PDF not available (Equifax sandbox limitation)`);
            storageUploadResult = { success: false, error: "Sandbox PDFs not available - Equifax limitation", isSandboxLimitation: true };
          } else {
            console.error(`[ObjectStorage] PDF upload failed:`, pdfError.message);
            storageUploadResult = { success: false, error: pdfError.message };
          }
        }
      }
      
      return res.json({
        ...formatFullReportForApi(savedReport),
        source: "equifax",
        pulledAt: new Date().toISOString(),
        rawEquifaxRequest: equifaxReport.rawEquifaxRequest,
        rawEquifaxResponse: equifaxReport.rawEquifaxResponse,
        pdfPath: equifaxReport.pdfPath,
        storageUpload: storageUploadResult,
      });
    } catch (error: any) {
      console.error("Error pulling credit report:", error);
      
      const message = error.message?.includes("Equifax")
        ? error.message
        : "Failed to pull credit report. Please try again.";
      
      // Include the original request (with SSN masked) for debugging
      const maskedRequest = {
        ...req.body,
        ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
      };
      
      return res.status(500).json({ 
        error: message,
        originalRequest: maskedRequest,
      });
    }
  });

  app.post("/api/equifax/prescreen", async (req, res) => {
    try {
      if (!equifaxClient.isPrescreenConfigured()) {
        return res.status(503).json({
          error: "Equifax Prescreen is not configured",
          missingSecrets: ["EQUIFAX_PRESCREEN_CLIENT_ID", "EQUIFAX_PRESCREEN_CLIENT_SECRET"],
          message: "Please add EQUIFAX_PRESCREEN_CLIENT_ID and EQUIFAX_PRESCREEN_CLIENT_SECRET secrets",
        });
      }

      const validationResult = prescreenRequestSchema.safeParse(req.body);
      if (!validationResult.success) {
        const validationError = fromError(validationResult.error);
        const maskedRequest = {
          ...req.body,
          ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
        };
        return res.status(400).json({ 
          error: validationError.toString(),
          originalRequest: maskedRequest,
        });
      }

      const request = validationResult.data;
      
      console.log(`[API] Running prescreen for ${request.firstName} ${request.lastName}`);
      const prescreenResult = await equifaxClient.prescreen(request);
      
      return res.json({
        decision: prescreenResult.decision,
        scoreUsed: prescreenResult.scoreUsed,
        scoreModel: prescreenResult.scoreModel,
        riskIndicators: prescreenResult.riskIndicators,
        pullType: "soft",
        processedAt: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error("Error performing prescreen:", error);
      
      const message = error.message?.includes("Equifax")
        ? error.message
        : "Failed to perform prescreen. Please try again.";
      
      // Include the original request (with SSN masked) for debugging
      const maskedRequest = {
        ...req.body,
        ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
      };
      
      return res.status(500).json({ 
        error: message,
        originalRequest: maskedRequest,
      });
    }
  });

  // Prequalification of One endpoint
  app.post("/api/equifax/prequalification-one", async (req, res) => {
    try {
      if (!equifaxClient.isPQOConfigured()) {
        const missingSecrets = equifaxClient.getMissingPQOConfig();
        return res.status(503).json({
          error: "Equifax Prequalification of One is not configured",
          missingSecrets,
          message: `Please add the following secrets: ${missingSecrets.join(", ")}`,
        });
      }

      const validationResult = creditReportRequestSchema.safeParse(req.body);
      if (!validationResult.success) {
        const validationError = fromError(validationResult.error);
        const maskedRequest = {
          ...req.body,
          ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
        };
        return res.status(400).json({ 
          error: validationError.toString(),
          originalRequest: maskedRequest,
        });
      }

      const request = validationResult.data;
      
      console.log(`[API] Running PQO for ${request.firstName} ${request.lastName}`);
      const pqoResult = await equifaxClient.prequalifyOne(request);
      
      return res.json({
        decision: pqoResult.decision,
        scoreUsed: pqoResult.scoreUsed,
        scoreModel: pqoResult.scoreModel,
        models: pqoResult.models,
        addresses: pqoResult.addresses,
        fraudIndicator: pqoResult.fraudIndicator,
        offers: pqoResult.offers,
        riskIndicators: pqoResult.riskIndicators,
        message: pqoResult.message,
        pullType: "soft",
        processedAt: new Date().toISOString(),
        requestUrl: pqoResult.requestUrl,
        requestHeaders: pqoResult.requestHeaders,
        rawEquifaxRequest: pqoResult.rawEquifaxRequest,
        rawEquifaxResponse: pqoResult.rawEquifaxResponse,
      });
    } catch (error: any) {
      console.error("Error performing PQO:", error);
      
      const message = error.message?.includes("Equifax") || error.message?.includes("PQO")
        ? error.message
        : "Failed to perform prequalification. Please try again.";
      
      const maskedRequest = {
        ...req.body,
        ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
      };
      
      return res.status(500).json({ 
        error: message,
        originalRequest: maskedRequest,
      });
    }
  });

  // Alias for PQO endpoint (shorter path)
  app.post("/api/equifax/pqo", async (req, res) => {
    try {
      if (!equifaxClient.isPQOConfigured()) {
        const missingSecrets = equifaxClient.getMissingPQOConfig();
        return res.status(503).json({
          error: "Equifax Prequalification of One is not configured",
          missingSecrets,
          message: `Please add the following secrets: ${missingSecrets.join(", ")}`,
        });
      }

      const validationResult = creditReportRequestSchema.safeParse(req.body);
      if (!validationResult.success) {
        const validationError = fromError(validationResult.error);
        const maskedRequest = {
          ...req.body,
          ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
        };
        return res.status(400).json({ 
          error: validationError.toString(),
          originalRequest: maskedRequest,
        });
      }

      const request = validationResult.data;
      
      console.log(`[API] Running PQO for ${request.firstName} ${request.lastName}`);
      const pqoResult = await equifaxClient.prequalifyOne(request);
      
      return res.json({
        decision: pqoResult.decision,
        scoreUsed: pqoResult.scoreUsed,
        scoreModel: pqoResult.scoreModel,
        models: pqoResult.models,
        addresses: pqoResult.addresses,
        fraudIndicator: pqoResult.fraudIndicator,
        offers: pqoResult.offers,
        riskIndicators: pqoResult.riskIndicators,
        message: pqoResult.message,
        pullType: "soft",
        processedAt: new Date().toISOString(),
        requestUrl: pqoResult.requestUrl,
        requestHeaders: pqoResult.requestHeaders,
        rawEquifaxRequest: pqoResult.rawEquifaxRequest,
        rawEquifaxResponse: pqoResult.rawEquifaxResponse,
      });
    } catch (error: any) {
      console.error("Error performing PQO:", error);
      
      const message = error.message?.includes("Equifax") || error.message?.includes("PQO")
        ? error.message
        : "Failed to perform prequalification. Please try again.";
      
      const maskedRequest = {
        ...req.body,
        ssn: req.body.ssn ? `***-**-${req.body.ssn.replace(/-/g, "").slice(-4)}` : undefined,
      };
      
      return res.status(500).json({ 
        error: message,
        originalRequest: maskedRequest,
      });
    }
  });

  // ============================================
  // EXTERNAL API ENDPOINT FOR THIRD-PARTY APPS
  // ============================================

  // External API schema - simplified input format
  const externalCreditRequestSchema = z.object({
    ssn: z.string().regex(/^\d{3}-?\d{2}-?\d{4}$/, "Invalid SSN format"),
    firstName: z.string().min(1, "First name is required"),
    lastName: z.string().min(1, "Last name is required"),
    middleName: z.string().optional(),
    dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be YYYY-MM-DD").optional(),
    address: z.object({
      street: z.string().min(1, "Street is required"),
      city: z.string().min(1, "City is required"),
      state: z.string().length(2, "State must be 2-letter code"),
      zipCode: z.string().regex(/^\d{5}(-\d{4})?$/, "Invalid ZIP code"),
    }),
  });

  // API Key authentication middleware
  const validateApiKey = (req: any, res: any, next: any) => {
    const apiKey = req.headers["x-api-key"] || req.headers["authorization"]?.replace("Bearer ", "");
    const validApiKey = process.env.CREDIT_API_KEY;

    if (!validApiKey) {
      return res.status(503).json({
        error: "API not configured",
        message: "CREDIT_API_KEY environment variable is not set",
      });
    }

    if (!apiKey || apiKey !== validApiKey) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Invalid or missing API key. Include X-API-Key header.",
      });
    }

    next();
  };

  // External API: Request a credit report
  app.post("/api/v1/credit-report", validateApiKey, async (req, res) => {
    try {
      // Check if Equifax is configured
      if (!equifaxClient.isConfigured()) {
        return res.status(503).json({
          error: "Service unavailable",
          message: "Credit reporting service is not fully configured",
        });
      }

      // Validate request
      const validationResult = externalCreditRequestSchema.safeParse(req.body);
      if (!validationResult.success) {
        const validationError = fromError(validationResult.error);
        return res.status(400).json({
          error: "Validation error",
          details: validationError.toString(),
        });
      }

      const request = validationResult.data;
      const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      console.log(`[External API] Credit report request ${requestId} for ${request.firstName} ${request.lastName}`);

      // Pull credit report from Equifax
      const equifaxReport = await equifaxClient.getCreditReport({
        firstName: request.firstName,
        lastName: request.lastName,
        middleName: request.middleName,
        ssn: request.ssn,
        dateOfBirth: request.dateOfBirth,
        address: request.address,
      });

      // Save to normalized tables with raw response for reparsing
      const savedReport = await saveNormalizedReport(equifaxReport, request.ssn || "", equifaxReport.rawEquifaxResponse, {
        firstName: request.firstName,
        lastName: request.lastName,
        middleName: request.middleName,
        ssn: request.ssn,
        dateOfBirth: request.dateOfBirth,
        street: request.address?.street,
        city: request.address?.city,
        state: request.address?.state,
        zip: request.address?.zipCode,
        source: "api",
      });

      // Return formatted response
      return res.json({
        requestId,
        status: "success",
        timestamp: new Date().toISOString(),
        consumer: {
          name: `${savedReport.consumer.firstName} ${savedReport.consumer.lastName}`,
          ssnLast4: savedReport.consumer.ssn.slice(-4),
          dateOfBirth: savedReport.consumer.dateOfBirth,
        },
        creditScores: savedReport.scores.map((score) => ({
          model: score.modelName || score.modelIdentifier,
          score: score.score,
          maxScore: score.maxScore || 850,
          rating: score.rating,
          factors: score.factors.map((f) => ({
            code: f.factorCode,
            description: f.factorDescription,
          })),
        })),
        tradelines: savedReport.tradelines.map((tl) => ({
          creditorName: tl.subscriberName,
          accountType: tl.accountType,
          currentBalance: tl.currentBalance,
          creditLimit: tl.creditLimit,
          status: tl.accountStatusDescription,
          dateOpened: tl.dateOpened,
        })),
        inquiries: {
          count: savedReport.inquiries.length,
          items: savedReport.inquiries.map((inq) => ({
            date: inq.inquiryDate,
            creditor: inq.customerName,
            type: inq.inquiryType,
          })),
        },
      });
    } catch (error: any) {
      console.error("[External API] Error:", error);
      return res.status(500).json({
        error: "Internal server error",
        message: error.message?.includes("Equifax") ? error.message : "Failed to retrieve credit report",
      });
    }
  });

  // External API: Get cached credit report by SSN
  app.get("/api/v1/credit-report/:ssn", validateApiKey, async (req, res) => {
    try {
      const { ssn } = req.params;
      const cleanSsn = ssn.replace(/-/g, "");
      
      const fullReport = await storage.getFullCreditReport(cleanSsn);
      
      if (!fullReport) {
        return res.status(404).json({
          error: "Not found",
          message: "No credit report found for this SSN",
        });
      }

      return res.json({
        status: "success",
        source: "cache",
        timestamp: fullReport.consumer.updatedAt,
        consumer: {
          name: `${fullReport.consumer.firstName} ${fullReport.consumer.lastName}`,
          ssnLast4: fullReport.consumer.ssn.slice(-4),
          dateOfBirth: fullReport.consumer.dateOfBirth,
        },
        creditScores: fullReport.scores.map((score) => ({
          model: score.modelName || score.modelIdentifier,
          score: score.score,
          maxScore: score.maxScore || 850,
          rating: score.rating,
        })),
        tradelines: fullReport.tradelines.map((tl) => ({
          creditorName: tl.subscriberName,
          accountType: tl.accountType,
          currentBalance: tl.currentBalance,
          creditLimit: tl.creditLimit,
          status: tl.accountStatusDescription,
        })),
        inquiryCount: fullReport.inquiries.length,
      });
    } catch (error: any) {
      console.error("[External API] Error fetching cached report:", error);
      return res.status(500).json({
        error: "Internal server error",
        message: "Failed to retrieve credit report",
      });
    }
  });

  // External API: Health check
  app.get("/api/v1/health", (req, res) => {
    return res.json({
      status: "healthy",
      version: "1.0",
      equifaxConfigured: equifaxClient.isConfigured(),
      prescreenConfigured: equifaxClient.isPrescreenConfigured(),
      pqoConfigured: equifaxClient.isPQOConfigured(),
      timestamp: new Date().toISOString(),
    });
  });

  // ============================================
  // OBJECT STORAGE ENDPOINTS (Replit Built-in)
  // ============================================

  app.get("/api/storage/status", async (req, res) => {
    const config = objectStorageService.getConfig();
    let bucketVerification = null;
    
    if (config.configured) {
      bucketVerification = await objectStorageService.verifyBucketAccess();
    }
    
    return res.json({
      configured: config.configured,
      directory: config.directory,
      autoUploadEnabled: config.configured && bucketVerification?.success,
      environment: equifaxClient.getActiveEnvironment(),
      bucketVerification,
    });
  });

  app.get("/api/storage/reports", async (req, res) => {
    const { environment } = req.query;
    const result = await objectStorageService.listReports(environment as string | undefined);
    
    if (!result.success) {
      return res.status(result.error?.includes("not set") ? 503 : 500).json({
        success: false,
        error: result.error,
        configured: objectStorageService.isConfigured(),
      });
    }
    
    return res.json({
      success: true,
      count: result.reports.length,
      reports: result.reports,
    });
  });

  // Serve PDF files from object storage
  app.get("/objects/:objectPath(*)", async (req, res) => {
    try {
      const objectPath = `/objects/${req.params.objectPath}`;
      const objectFile = await objectStorageService.getObjectEntityFile(objectPath);
      await objectStorageService.downloadObject(objectFile, res);
    } catch (error) {
      if (error instanceof ObjectNotFoundError) {
        return res.status(404).json({ error: "File not found" });
      }
      console.error("Error serving object:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  // Get stored PDF images from object storage (pre-converted)
  app.get("/api/stored-pdf-images/:objectPath(*)", async (req, res) => {
    try {
      const rawPath = req.params.objectPath;
      
      // Security: Prevent path traversal attacks
      if (rawPath.includes("..") || rawPath.includes("//") || /[<>:|"?*\\]/.test(rawPath)) {
        return res.status(400).json({ error: "Invalid path" });
      }
      
      const normalizedPath = rawPath.replace(/^\/+/, "").replace(/\/+/g, "/");
      if (!normalizedPath || normalizedPath.length > 500) {
        return res.status(400).json({ error: "Invalid path" });
      }
      
      const objectPath = `/objects/${normalizedPath}`;
      const result = await objectStorageService.getPdfImagesFromStorage(objectPath);
      
      if (!result.success) {
        return res.status(404).json({ error: result.error || "Stored images not found" });
      }
      
      return res.json({
        success: true,
        pageCount: result.pageCount,
        pages: result.pages,
      });
    } catch (error) {
      console.error("Error retrieving stored PDF images:", error);
      return res.status(500).json({ error: "Failed to retrieve stored images" });
    }
  });

  // Convert PDF to images for inline display
  app.get("/api/pdf-images/:objectPath(*)", async (req, res) => {
    try {
      const rawPath = req.params.objectPath;
      
      // Security: Prevent path traversal attacks
      if (rawPath.includes("..") || rawPath.includes("//") || /[<>:|"?*\\]/.test(rawPath)) {
        return res.status(400).json({ error: "Invalid path" });
      }
      
      // Normalize and validate path
      const normalizedPath = rawPath.replace(/^\/+/, "").replace(/\/+/g, "/");
      if (!normalizedPath || normalizedPath.length > 500) {
        return res.status(400).json({ error: "Invalid path" });
      }
      
      const objectPath = `/objects/${normalizedPath}`;
      const objectFile = await objectStorageService.getObjectEntityFile(objectPath);
      
      // Download PDF to buffer
      const [buffer] = await objectFile.download();
      
      // Convert PDF to images
      const { convertPdfToImages } = await import("./pdfConverter");
      const pages = await convertPdfToImages(buffer, 1.5);
      
      if (pages.length === 0) {
        return res.json({
          success: false,
          error: "PDF contains no pages or could not be converted",
          pageCount: 0,
          pages: [],
        });
      }
      
      return res.json({
        success: true,
        pageCount: pages.length,
        pages,
      });
    } catch (error) {
      if (error instanceof ObjectNotFoundError) {
        return res.status(404).json({ error: "PDF not found" });
      }
      console.error("Error converting PDF to images:", error);
      return res.status(500).json({ error: "Failed to convert PDF" });
    }
  });

  // Fetch and save PDF for a consumer that has link but no saved PDF (backfill)
  app.post("/api/consumers/:id/fetch-pdf", async (req, res) => {
    try {
      const { id } = req.params;
      const consumer = await storage.getConsumerById(id);
      
      if (!consumer) {
        return res.status(404).json({ error: "Consumer not found" });
      }
      
      // Check if PDF already exists
      if (consumer.pdfStoragePath) {
        console.log(`[API] Consumer ${id} already has PDF at ${consumer.pdfStoragePath}`);
        return res.json({ 
          success: true, 
          message: "PDF already exists",
          pdfStoragePath: consumer.pdfStoragePath,
          skipped: true
        });
      }
      
      // Extract PDF path from raw response
      const rawResponse = consumer.rawEquifaxResponse as Record<string, any> | null;
      if (!rawResponse) {
        return res.status(400).json({ error: "No raw Equifax response stored for this consumer" });
      }
      
      const links = rawResponse.links || [];
      let pdfPath: string | undefined;
      
      if (Array.isArray(links) && links.length > 0) {
        // First try to find an explicit PDF link (same logic as getCreditReport)
        let pdfLink = links.find((link: any) => {
          const type = (link.type || "").toLowerCase();
          const rel = (link.rel || "").toLowerCase();
          const href = (link.href || "").toLowerCase();
          return type.includes("pdf") || 
                 rel.includes("pdf") || 
                 href.includes("/pdf") ||
                 link.identifier?.toLowerCase().includes("pdf");
        });
        
        // If no explicit PDF link, use the first GET link (strip trailing commas)
        if (!pdfLink) {
          pdfLink = links.find((link: any) => {
            const type = (link.type || "").toUpperCase().replace(/[,\s]/g, "");
            return type === "GET" && link.href;
          });
        }
        
        if (pdfLink?.href) {
          pdfPath = pdfLink.href;
        }
      }
      
      if (!pdfPath) {
        return res.status(400).json({ error: "No PDF link found in stored response" });
      }
      
      // Switch to consumer's environment before fetching, then restore
      const consumerEnv = consumer.environment as "sandbox" | "test" | "production" || "sandbox";
      const originalEnv = equifaxClient.getActiveEnvironment();
      const needsEnvSwitch = consumerEnv !== originalEnv;
      
      try {
        if (needsEnvSwitch) {
          console.log(`[API] Switching environment from ${originalEnv} to ${consumerEnv} for PDF fetch`);
          equifaxClient.setActiveEnvironment(consumerEnv);
        }
        
        console.log(`[API] Fetching PDF for consumer ${id} from: ${pdfPath}`);
        
        // Note: Equifax sandbox may not support PDF retrieval (returns 406)
        // This is a known limitation of their sandbox environment
        let pdfBuffer: Buffer;
        try {
          pdfBuffer = await equifaxClient.fetchPdf(pdfPath);
        } catch (fetchError: any) {
          if (fetchError.message?.includes("406")) {
            return res.status(400).json({ 
              error: "PDF not available - Equifax sandbox does not support PDF retrieval. PDFs are only available for production reports.",
              isSandboxLimitation: true
            });
          }
          throw fetchError;
        }
        
        // Upload to storage
        const consumerName = `${consumer.requestFirstName || consumer.firstName || ''} ${consumer.requestLastName || consumer.lastName || ''}`.trim() || 'unknown';
        const activeEnv = consumer.environment || equifaxClient.getActiveEnvironment();
        
        const uploadResult = await objectStorageService.uploadPdf(
          pdfBuffer,
          consumerName,
          consumer.ssn || "",
          activeEnv
        );
        
        if (!uploadResult.success || !uploadResult.objectPath) {
          return res.status(500).json({ error: uploadResult.error || "Failed to upload PDF" });
        }
        
        // Update consumer record
        await storage.updateConsumer(id, {
          pdfStoragePath: uploadResult.objectPath,
        });
        
        console.log(`[API] PDF saved for consumer ${id}: ${uploadResult.objectPath}`);
        
        // Also convert to images
        try {
          const { convertPdfToImages } = await import("./pdfConverter");
          const pages = await convertPdfToImages(pdfBuffer, 1.5);
          
          if (pages.length > 0) {
            const imagesResult = await objectStorageService.uploadPdfImages(
              pages,
              consumerName,
              consumer.id,
              consumer.ssn || "",
              activeEnv
            );
            
            if (imagesResult.success && imagesResult.objectPath) {
              await storage.updateConsumer(id, {
                pdfImageStoragePath: imagesResult.objectPath,
              });
              console.log(`[API] PDF images saved for consumer ${id}: ${imagesResult.objectPath}`);
            }
          }
        } catch (imgError: any) {
          console.error(`[API] Image conversion failed but PDF was saved:`, imgError.message);
        }
        
        return res.json({
          success: true,
          message: "PDF fetched and saved successfully",
          pdfStoragePath: uploadResult.objectPath,
        });
      } finally {
        // Always restore original environment
        if (needsEnvSwitch) {
          console.log(`[API] Restoring environment to ${originalEnv}`);
          equifaxClient.setActiveEnvironment(originalEnv);
        }
      }
    } catch (error: any) {
      console.error("Error fetching PDF for consumer:", error);
      return res.status(500).json({ error: error.message || "Failed to fetch PDF" });
    }
  });

  // Regenerate PDF images for a consumer (backfill existing records)
  app.post("/api/consumers/:id/regenerate-images", async (req, res) => {
    try {
      const { id } = req.params;
      const consumer = await storage.getConsumerById(id);
      
      if (!consumer) {
        return res.status(404).json({ error: "Consumer not found" });
      }
      
      // Check if images already exist
      if (consumer.pdfImageStoragePath) {
        console.log(`[API] Consumer ${id} already has stored images at ${consumer.pdfImageStoragePath}`);
        return res.json({ 
          success: true, 
          message: "Images already exist",
          pdfImageStoragePath: consumer.pdfImageStoragePath,
          skipped: true
        });
      }
      
      // Check if PDF exists in storage
      if (!consumer.pdfStoragePath) {
        return res.status(400).json({ error: "Consumer has no stored PDF to convert" });
      }
      
      console.log(`[API] Regenerating images for consumer ${id} from ${consumer.pdfStoragePath}`);
      
      // Download PDF from storage
      const objectFile = await objectStorageService.getObjectEntityFile(consumer.pdfStoragePath);
      const [pdfBuffer] = await objectFile.download();
      
      // Convert to images
      const { convertPdfToImages } = await import("./pdfConverter");
      const pages = await convertPdfToImages(pdfBuffer, 1.5);
      
      if (pages.length === 0) {
        return res.status(500).json({ error: "PDF contains no pages or could not be converted" });
      }
      
      // Upload images to storage
      const consumerName = `${consumer.firstName || ''} ${consumer.lastName || ''}`.trim() || 'unknown';
      const imagesResult = await objectStorageService.uploadPdfImages(
        pages,
        consumerName,
        consumer.id,
        consumer.ssn || "",
        consumer.environment || "production"
      );
      
      if (!imagesResult.success || !imagesResult.objectPath) {
        return res.status(500).json({ error: imagesResult.error || "Failed to upload images" });
      }
      
      // Update consumer record
      await storage.updateConsumer(id, {
        pdfImageStoragePath: imagesResult.objectPath,
      });
      
      console.log(`[API] Images regenerated for consumer ${id}: ${imagesResult.objectPath}`);
      
      return res.json({
        success: true,
        message: "Images regenerated successfully",
        pdfImageStoragePath: imagesResult.objectPath,
        pageCount: pages.length,
      });
    } catch (error: any) {
      console.error("Error regenerating images:", error);
      return res.status(500).json({ error: error.message || "Failed to regenerate images" });
    }
  });

  // IP Whitelist Settings Routes (must be defined before /api/settings/:key)
  app.get("/api/settings/ip-whitelist", async (req, res) => {
    try {
      const ips = await storage.getAllWhitelistedIps();
      return res.json(ips);
    } catch (error: any) {
      console.error("Error fetching IP whitelist:", error);
      return res.status(500).json({ error: "Failed to fetch IP whitelist" });
    }
  });

  app.post("/api/settings/ip-whitelist", async (req, res) => {
    try {
      const { ipAddress, description, isEnabled } = req.body;
      
      if (!ipAddress || typeof ipAddress !== "string") {
        return res.status(400).json({ error: "IP address is required" });
      }
      
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$|^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^\*$/;
      if (!ipPattern.test(ipAddress) && ipAddress !== "*") {
        return res.status(400).json({ error: "Invalid IP address format" });
      }
      
      const newIp = await storage.createWhitelistedIp({
        ipAddress,
        description: description || null,
        isEnabled: isEnabled !== false,
      });
      
      console.log(`[Settings] Added IP to whitelist: ${ipAddress}`);
      return res.json(newIp);
    } catch (error: any) {
      console.error("Error adding IP to whitelist:", error);
      if (error.message?.includes("unique") || error.code === "23505") {
        return res.status(400).json({ error: "This IP address is already in the whitelist" });
      }
      return res.status(500).json({ error: "Failed to add IP to whitelist" });
    }
  });

  app.put("/api/settings/ip-whitelist/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { ipAddress, description, isEnabled } = req.body;
      
      const existing = await storage.getWhitelistedIpById(id);
      if (!existing) {
        return res.status(404).json({ error: "IP not found" });
      }
      
      if (ipAddress) {
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$|^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^\*$/;
        if (!ipPattern.test(ipAddress) && ipAddress !== "*") {
          return res.status(400).json({ error: "Invalid IP address format" });
        }
      }
      
      const updated = await storage.updateWhitelistedIp(id, {
        ipAddress: ipAddress ?? existing.ipAddress,
        description: description !== undefined ? description : existing.description,
        isEnabled: isEnabled !== undefined ? isEnabled : existing.isEnabled,
      });
      
      console.log(`[Settings] Updated IP whitelist entry: ${id}`);
      return res.json(updated);
    } catch (error: any) {
      console.error("Error updating IP whitelist:", error);
      if (error.message?.includes("unique") || error.code === "23505") {
        return res.status(400).json({ error: "This IP address is already in the whitelist" });
      }
      return res.status(500).json({ error: "Failed to update IP whitelist" });
    }
  });

  app.delete("/api/settings/ip-whitelist/:id", async (req, res) => {
    try {
      const { id } = req.params;
      
      const existing = await storage.getWhitelistedIpById(id);
      if (!existing) {
        return res.status(404).json({ error: "IP not found" });
      }
      
      await storage.deleteWhitelistedIp(id);
      console.log(`[Settings] Deleted IP from whitelist: ${existing.ipAddress}`);
      return res.json({ success: true });
    } catch (error: any) {
      console.error("Error deleting IP from whitelist:", error);
      return res.status(500).json({ error: "Failed to delete IP from whitelist" });
    }
  });

  // App Settings Routes (must be defined after specific /api/settings/* routes)
  app.get("/api/settings/app", async (req, res) => {
    try {
      const settings = await storage.getAllAppSettings();
      const settingsMap: Record<string, string> = {};
      for (const s of settings) {
        settingsMap[s.key] = s.value;
      }
      return res.json(settingsMap);
    } catch (error: any) {
      console.error("Error fetching settings:", error);
      return res.status(500).json({ error: "Failed to fetch settings" });
    }
  });

  app.get("/api/settings/app/:key", async (req, res) => {
    try {
      const { key } = req.params;
      const value = await storage.getAppSetting(key);
      return res.json({ key, value });
    } catch (error: any) {
      console.error("Error fetching setting:", error);
      return res.status(500).json({ error: "Failed to fetch setting" });
    }
  });

  app.put("/api/settings/app/:key", async (req, res) => {
    try {
      const { key } = req.params;
      const { value, description } = req.body;
      
      if (value === undefined || value === null) {
        return res.status(400).json({ error: "Value is required" });
      }
      
      const setting = await storage.setAppSetting(key, String(value), description);
      console.log(`[Settings] Updated setting: ${key} = ${value}`);
      return res.json(setting);
    } catch (error: any) {
      console.error("Error updating setting:", error);
      return res.status(500).json({ error: "Failed to update setting" });
    }
  });

  // Geocoding API Endpoints
  app.post("/api/geocode", async (req, res) => {
    const { address } = req.body;
    
    if (!address || typeof address !== "string") {
      return res.status(400).json({ error: "Address is required" });
    }

    const results: {
      census: any;
      google: any;
      usps: any;
    } = {
      census: null,
      google: null,
      usps: null,
    };

    // Query US Census Geocoder (free, no API key required)
    try {
      const censusUrl = new URL("https://geocoding.geo.census.gov/geocoder/geographies/onelineaddress");
      censusUrl.searchParams.set("address", address);
      censusUrl.searchParams.set("benchmark", "Public_AR_Current");
      censusUrl.searchParams.set("vintage", "Current_Current");
      censusUrl.searchParams.set("format", "json");

      console.log(`[Geocoding] Census request: ${censusUrl.toString()}`);
      const censusResponse = await fetch(censusUrl.toString());
      const censusData = await censusResponse.json();

      if (censusData.result?.addressMatches?.length > 0) {
        const match = censusData.result.addressMatches[0];
        const geographies = match.geographies;
        
        // Extract FIPS codes for income lookup
        const stateFips = geographies?.States?.[0]?.STATE || null;
        const countyFips = geographies?.Counties?.[0]?.COUNTY || null;
        const tractCode = geographies?.["Census Tracts"]?.[0]?.TRACT || null;
        const tractGeoid = geographies?.["Census Tracts"]?.[0]?.GEOID || null;

        results.census = {
          matched: true,
          matchedAddress: match.matchedAddress,
          coordinates: {
            latitude: match.coordinates?.y,
            longitude: match.coordinates?.x,
          },
          county: geographies?.Counties?.[0]?.NAME || null,
          state: geographies?.States?.[0]?.NAME || null,
          tract: geographies?.["Census Tracts"]?.[0]?.NAME || null,
          tractGeoid: tractGeoid,
          blockGroup: geographies?.["Census Block Groups"]?.[0]?.NAME || null,
          stateFips,
          countyFips,
          tractCode,
          raw: censusData,
        };

        // Fetch income data from Census ACS API if we have tract info
        if (stateFips && countyFips && tractCode) {
          try {
            const acsUrl = `https://api.census.gov/data/2022/acs/acs5?get=NAME,B19013_001E,B19019_001E,B19301_001E&for=tract:${tractCode}&in=state:${stateFips}&in=county:${countyFips}`;
            console.log(`[Geocoding] ACS income request: ${acsUrl}`);
            const acsResponse = await fetch(acsUrl);
            const acsData = await acsResponse.json();
            
            if (Array.isArray(acsData) && acsData.length > 1) {
              const [headers, values] = acsData;
              results.census.income = {
                medianHouseholdIncome: values[1] ? parseInt(values[1]) : null,
                medianFamilyIncome: values[2] ? parseInt(values[2]) : null,
                perCapitaIncome: values[3] ? parseInt(values[3]) : null,
                source: "American Community Survey 5-Year (2022)",
              };
            }
          } catch (acsError: any) {
            console.error("[Geocoding] ACS API error:", acsError.message);
            results.census.incomeError = acsError.message;
          }

          // Fetch FFIEC LMI designation
          try {
            const ffiecUrl = `https://geomap.ffiec.gov/FFIECGeocMap/GeocodeMap1.aspx/GetGeocodeData`;
            // Note: FFIEC doesn't have a simple REST API, so we'll calculate LMI based on HUD thresholds
            // For now, we'll use a simplified approach based on median income vs area median
            // A tract is considered LMI if median income is <80% of area median
            
            // Query for MSA/state median income for comparison
            const stateAcsUrl = `https://api.census.gov/data/2022/acs/acs5?get=B19013_001E&for=state:${stateFips}`;
            const stateAcsResponse = await fetch(stateAcsUrl);
            const stateAcsData = await stateAcsResponse.json();
            
            if (Array.isArray(stateAcsData) && stateAcsData.length > 1 && results.census.income?.medianHouseholdIncome) {
              const stateMedianIncome = parseInt(stateAcsData[1][0]);
              const tractMedianIncome = results.census.income.medianHouseholdIncome;
              const incomeRatio = (tractMedianIncome / stateMedianIncome) * 100;
              
              let lmiDesignation: string;
              if (incomeRatio < 50) {
                lmiDesignation = "Low";
              } else if (incomeRatio < 80) {
                lmiDesignation = "Moderate";
              } else if (incomeRatio < 120) {
                lmiDesignation = "Middle";
              } else {
                lmiDesignation = "Upper";
              }
              
              results.census.lmi = {
                designation: lmiDesignation,
                tractMedianIncome,
                stateMedianIncome,
                incomeRatioPercent: Math.round(incomeRatio),
                isLmiTract: incomeRatio < 80,
                description: `Tract income is ${Math.round(incomeRatio)}% of state median`,
              };
            }
          } catch (lmiError: any) {
            console.error("[Geocoding] LMI calculation error:", lmiError.message);
          }
        }
      } else {
        results.census = {
          matched: false,
          message: "No address match found",
          raw: censusData,
        };
      }
    } catch (error: any) {
      console.error("[Geocoding] Census API error:", error.message);
      results.census = {
        error: true,
        message: error.message,
      };
    }

    // Query Google Maps Geocoding API (requires API key)
    const googleApiKey = process.env.GOOGLE_MAPS_API_KEY;
    if (googleApiKey) {
      try {
        const googleUrl = new URL("https://maps.googleapis.com/maps/api/geocode/json");
        googleUrl.searchParams.set("address", address);
        googleUrl.searchParams.set("key", googleApiKey);

        console.log(`[Geocoding] Google Maps request for: ${address}`);
        const googleResponse = await fetch(googleUrl.toString());
        const googleData = await googleResponse.json();

        if (googleData.status === "OK" && googleData.results?.length > 0) {
          const result = googleData.results[0];
          const location = result.geometry?.location;
          
          const getComponent = (type: string) => {
            const component = result.address_components?.find((c: any) => c.types?.includes(type));
            return component?.long_name || null;
          };
          
          // City extraction - check multiple component types in priority order
          // Some cities like San Antonio may be returned as sublocality or postal_town
          const getCityComponent = () => {
            const cityTypes = ["locality", "postal_town", "sublocality_level_1", "sublocality", "administrative_area_level_3"];
            for (const type of cityTypes) {
              const value = getComponent(type);
              if (value) return value;
            }
            return null;
          };

          results.google = {
            configured: true,
            matched: true,
            formattedAddress: result.formatted_address,
            coordinates: {
              latitude: location?.lat,
              longitude: location?.lng,
            },
            county: getComponent("administrative_area_level_2"),
            state: getComponent("administrative_area_level_1"),
            city: getCityComponent(),
            zipCode: getComponent("postal_code"),
            placeId: result.place_id,
            raw: googleData,
          };
        } else {
          results.google = {
            configured: true,
            matched: false,
            message: googleData.status === "ZERO_RESULTS" ? "No address match found" : googleData.status,
            raw: googleData,
          };
        }
      } catch (error: any) {
        console.error("[Geocoding] Google Maps API error:", error.message);
        results.google = {
          configured: true,
          error: true,
          message: error.message,
        };
      }
    } else {
      results.google = {
        configured: false,
        message: "Google Maps API key not configured",
      };
    }

    // Query USPS Address Validation API using OAuth 2.0 with credential rotation
    try {
      // Get an active credential from the database
      const credentials = await storage.getActiveUspsCredentials();
      
      if (credentials.length === 0) {
        results.usps = {
          configured: false,
          message: "No USPS credentials available in database",
        };
      } else {
        // Try credentials in rotation until one works
        let uspsSuccess = false;
        let lastError = "";
        
        for (const cred of credentials) {
          try {
            console.log(`[Geocoding] Trying USPS credential: ${cred.name || cred.id}`);
            
            // Get OAuth access token
            const tokenResponse = await fetch("https://apis.usps.com/oauth2/v3/token", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                client_id: cred.clientId,
                client_secret: cred.clientSecret,
                grant_type: "client_credentials",
              }),
            });
            
            if (!tokenResponse.ok) {
              const tokenError = await tokenResponse.text();
              console.log(`[Geocoding] USPS OAuth failed for ${cred.name || cred.id}: ${tokenError}`);
              lastError = `OAuth failed: ${tokenResponse.status}`;
              continue; // Try next credential
            }
            
            const tokenData = await tokenResponse.json();
            const accessToken = tokenData.access_token;
            
            if (!accessToken) {
              console.log(`[Geocoding] No access token returned for ${cred.name || cred.id}`);
              lastError = "No access token returned";
              continue;
            }
            
            // Parse address into components for USPS API
            // Prefer using Google's parsed results if available
            let street = "";
            let city = "";
            let stateCode = "";
            let zipCode = "";
            
            if (results.google?.matched && results.google.raw?.results?.[0]?.address_components) {
              const components = results.google.raw.results[0].address_components;
              const getComp = (type: string) => components.find((c: any) => c.types.includes(type))?.short_name || "";
              const getLongComp = (type: string) => components.find((c: any) => c.types.includes(type))?.long_name || "";
              
              const streetNumber = getComp("street_number");
              const route = getLongComp("route");
              street = streetNumber ? `${streetNumber} ${route}` : route;
              city = getComp("locality") || getComp("sublocality") || getComp("postal_town") || "";
              stateCode = getComp("administrative_area_level_1");
              zipCode = getComp("postal_code");
            } else {
              // Fallback to comma-based parsing
              const addressParts = address.split(",").map((p: string) => p.trim());
              street = addressParts[0] || "";
              
              if (addressParts.length >= 2) {
                city = addressParts[1] || "";
              }
              if (addressParts.length >= 3) {
                const stateZip = addressParts[2].trim().split(" ");
                stateCode = stateZip[0] || "";
                zipCode = stateZip[1] || "";
              }
              if (addressParts.length >= 4) {
                zipCode = addressParts[3].trim();
              }
            }
            
            // Call USPS Address API v3
            const uspsApiUrl = new URL("https://apis.usps.com/addresses/v3/address");
            uspsApiUrl.searchParams.set("streetAddress", street);
            if (city) uspsApiUrl.searchParams.set("city", city);
            if (stateCode) uspsApiUrl.searchParams.set("state", stateCode);
            if (zipCode) uspsApiUrl.searchParams.set("ZIPCode", zipCode);
            
            console.log(`[Geocoding] USPS API request: ${uspsApiUrl.toString()}`);
            
            const uspsResponse = await fetch(uspsApiUrl.toString(), {
              headers: {
                "Authorization": `Bearer ${accessToken}`,
                "Accept": "application/json",
              },
            });
            
            // Update credential usage
            await storage.updateUspsCredentialUsage(cred.id);
            
            if (!uspsResponse.ok) {
              const errorText = await uspsResponse.text();
              console.log(`[Geocoding] USPS API error for ${cred.name || cred.id}: ${uspsResponse.status} - ${errorText}`);
              
              // If rate limited or unauthorized, try next credential
              if (uspsResponse.status === 429 || uspsResponse.status === 401 || uspsResponse.status === 403) {
                lastError = `API error: ${uspsResponse.status}`;
                continue;
              }
              
              // Other errors, still report but don't try more credentials
              results.usps = {
                configured: true,
                matched: false,
                error: true,
                message: `USPS API error: ${uspsResponse.status}`,
                raw: errorText,
              };
              uspsSuccess = true;
              break;
            }
            
            const uspsData = await uspsResponse.json();
            console.log(`[Geocoding] USPS API success with ${cred.name || cred.id}`);
            
            // Extract address data from response
            const uspsAddress = uspsData.address || uspsData;
            
            if (uspsAddress.streetAddress || uspsAddress.city) {
              // Extract corrections from the raw response
              const corrections = uspsData.corrections || [];
              
              results.usps = {
                configured: true,
                matched: true,
                address1: uspsAddress.secondaryAddress || "",
                address2: uspsAddress.streetAddress || "",
                city: uspsAddress.city || "",
                state: uspsAddress.state || "",
                zip5: uspsAddress.ZIPCode || "",
                zip4: uspsAddress.ZIPPlus4 || "",
                fullZip: uspsAddress.ZIPPlus4 
                  ? `${uspsAddress.ZIPCode}-${uspsAddress.ZIPPlus4}` 
                  : uspsAddress.ZIPCode || "",
                deliveryPoint: uspsAddress.deliveryPoint || "",
                carrierRoute: uspsAddress.carrierRoute || "",
                dpvConfirmation: uspsAddress.DPVConfirmation || "",
                dpvFootnotes: uspsAddress.footnotes?.join(", ") || "",
                residential: uspsAddress.business === "N" ? "Y" : (uspsAddress.business === "Y" ? "N" : ""),
                recordType: uspsAddress.addressType || "",
                corrections: corrections.map((c: any) => ({
                  code: c.code || "",
                  text: c.text || "",
                })),
                raw: uspsData,
              };
            } else {
              results.usps = {
                configured: true,
                matched: false,
                message: "No USPS match found",
                raw: uspsData,
              };
            }
            
            uspsSuccess = true;
            break; // Success, exit credential loop
            
          } catch (credError: any) {
            console.error(`[Geocoding] USPS error with ${cred.name || cred.id}:`, credError.message);
            lastError = credError.message;
            // Continue to next credential
          }
        }
        
        if (!uspsSuccess) {
          results.usps = {
            configured: true,
            error: true,
            message: `All USPS credentials failed. Last error: ${lastError}`,
          };
        }
      }
    } catch (error: any) {
      console.error("[Geocoding] USPS credential rotation error:", error.message);
      results.usps = {
        configured: false,
        error: true,
        message: error.message,
      };
    }

    // Normalize the address before saving
    const normalizedAddressData = normalizeAddress({
      google: results.google ? {
        matched: results.google.matched,
        raw: results.google.raw,
        city: results.google.city,
        county: results.google.county,
        state: results.google.state,
        zipCode: results.google.zipCode,
        formattedAddress: results.google.formattedAddress,
        coordinates: results.google.coordinates,
      } : null,
      usps: results.usps ? {
        matched: results.usps.matched,
        city: results.usps.city,
        state: results.usps.state,
        zip5: results.usps.zip5,
        zip4: results.usps.zip4,
        address2: results.usps.address2,
        corrections: results.usps.corrections,
      } : null,
      census: results.census ? {
        matched: results.census.matched,
        matchedAddress: results.census.matchedAddress,
        county: results.census.county,
        state: results.census.state,
        coordinates: results.census.coordinates,
      } : null,
    });

    // Save geocoding results to database
    try {
      // Build insert data with explicit boolean coercion and null handling
      const insertData: any = {
        inputAddress: address,
        
        // Census data - explicit boolean coercion
        censusMatched: results.census?.matched === true,
        censusMatchedAddress: results.census?.matchedAddress ?? null,
        censusLatitude: results.census?.coordinates?.latitude != null ? String(results.census.coordinates.latitude) : null,
        censusLongitude: results.census?.coordinates?.longitude != null ? String(results.census.coordinates.longitude) : null,
        censusCounty: results.census?.county ?? null,
        censusState: results.census?.state ?? null,
        censusTract: results.census?.tract ?? null,
        censusTractGeoid: results.census?.tractGeoid ?? null,
        censusBlockGroup: results.census?.blockGroup ?? null,
        censusStateFips: results.census?.stateFips ?? null,
        censusCountyFips: results.census?.countyFips ?? null,
        censusTractCode: results.census?.tractCode ?? null,
        
        // Google data - explicit boolean coercion
        googleMatched: results.google?.matched === true,
        googleFormattedAddress: results.google?.formattedAddress ?? null,
        googleLatitude: results.google?.coordinates?.latitude != null ? String(results.google.coordinates.latitude) : null,
        googleLongitude: results.google?.coordinates?.longitude != null ? String(results.google.coordinates.longitude) : null,
        googleCounty: results.google?.county ?? null,
        googleState: results.google?.state ?? null,
        googleCity: results.google?.city ?? null,
        googleZipCode: results.google?.zipCode ?? null,
        googlePlaceId: results.google?.placeId ?? null,
        
        // Income data - explicit number handling
        medianHouseholdIncome: results.census?.income?.medianHouseholdIncome != null ? Number(results.census.income.medianHouseholdIncome) : null,
        medianFamilyIncome: results.census?.income?.medianFamilyIncome != null ? Number(results.census.income.medianFamilyIncome) : null,
        perCapitaIncome: results.census?.income?.perCapitaIncome != null ? Number(results.census.income.perCapitaIncome) : null,
        incomeSource: results.census?.income?.source ?? null,
        
        // LMI data - explicit boolean and number handling
        lmiDesignation: results.census?.lmi?.designation ?? null,
        lmiTractMedianIncome: results.census?.lmi?.tractMedianIncome != null ? Number(results.census.lmi.tractMedianIncome) : null,
        lmiStateMedianIncome: results.census?.lmi?.stateMedianIncome != null ? Number(results.census.lmi.stateMedianIncome) : null,
        lmiIncomeRatioPercent: results.census?.lmi?.incomeRatioPercent != null ? Number(results.census.lmi.incomeRatioPercent) : null,
        isLmiTract: results.census?.lmi?.isLmiTract === true,
        
        // USPS data
        uspsMatched: results.usps?.matched === true,
        uspsAddress1: results.usps?.address1 ?? null,
        uspsAddress2: results.usps?.address2 ?? null,
        uspsCity: results.usps?.city ?? null,
        uspsState: results.usps?.state ?? null,
        uspsZip5: results.usps?.zip5 ?? null,
        uspsZip4: results.usps?.zip4 ?? null,
        uspsDeliveryPoint: results.usps?.deliveryPoint ?? null,
        uspsCarrierRoute: results.usps?.carrierRoute ?? null,
        uspsDpvConfirmation: results.usps?.dpvConfirmation ?? null,
        uspsDpvFootnotes: results.usps?.dpvFootnotes ?? null,
        uspsResidentialIndicator: results.usps?.residential ?? null,
        uspsRecordType: results.usps?.recordType ?? null,
        uspsError: results.usps?.error ? results.usps.message : null,
        source: "browser",
        normalizedAddress: normalizedAddressData,
      };
      
      const savedAddress = await storage.createGeocodedAddress(insertData);
      
      console.log(`[Geocoding] Saved address lookup: ${savedAddress.id}`);
      
      // Include the saved ID and normalized address in the response
      return res.json({ ...results, savedId: savedAddress.id, normalizedAddress: normalizedAddressData });
    } catch (saveError: any) {
      console.error("[Geocoding] Failed to save address:", saveError.message);
      // Return results with save error flag
      return res.json({ ...results, saveError: saveError.message, normalizedAddress: normalizedAddressData });
    }
  });

  // Get all saved geocoded addresses
  app.get("/api/geocoded-addresses", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const addresses = await storage.getAllGeocodedAddresses(limit);
      return res.json(addresses);
    } catch (error: any) {
      console.error("[Geocoding] Failed to fetch addresses:", error.message);
      return res.status(500).json({ error: "Failed to fetch geocoded addresses" });
    }
  });

  // Get a specific geocoded address by ID
  app.get("/api/geocoded-addresses/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const address = await storage.getGeocodedAddressById(id);
      
      if (!address) {
        return res.status(404).json({ error: "Address not found" });
      }
      
      return res.json(address);
    } catch (error: any) {
      console.error("[Geocoding] Failed to fetch address:", error.message);
      return res.status(500).json({ error: "Failed to fetch geocoded address" });
    }
  });

  // Delete a geocoded address
  app.delete("/api/geocoded-addresses/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteGeocodedAddress(id);
      return res.json({ success: true });
    } catch (error: any) {
      console.error("[Geocoding] Failed to delete address:", error.message);
      return res.status(500).json({ error: "Failed to delete geocoded address" });
    }
  });

  // Check geocoding configuration status
  app.get("/api/geocode/status", async (req, res) => {
    return res.json({
      census: {
        configured: true,
        name: "US Census Geocoder",
        description: "Free government geocoding service with county/tract data",
      },
      google: {
        configured: !!process.env.GOOGLE_MAPS_API_KEY,
        name: "Google Maps Geocoding API",
        description: "Commercial geocoding with detailed place information",
      },
    });
  });

  // Google Places API (New) - Business name autocomplete search
  app.get("/api/places/autocomplete", async (req, res) => {
    const googleApiKey = process.env.GOOGLE_MAPS_API_KEY;
    if (!googleApiKey) {
      return res.status(400).json({ error: "Google Maps API key not configured", configured: false });
    }

    const { input } = req.query;
    if (!input || typeof input !== "string") {
      return res.status(400).json({ error: "Search input is required" });
    }

    try {
      console.log(`[Places] Autocomplete search: ${input}`);
      
      const response = await fetch("https://places.googleapis.com/v1/places:autocomplete", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Goog-Api-Key": googleApiKey,
        },
        body: JSON.stringify({
          input: input,
          includedPrimaryTypes: ["establishment"],
          includedRegionCodes: ["us"],
        }),
      });
      
      const data = await response.json();

      if (data.error) {
        console.error("[Places] API error:", data.error.message);
        return res.status(500).json({ error: data.error.message });
      }

      return res.json({
        predictions: (data.suggestions || []).map((s: any) => ({
          placeId: s.placePrediction?.placeId,
          description: s.placePrediction?.text?.text,
          mainText: s.placePrediction?.structuredFormat?.mainText?.text,
          secondaryText: s.placePrediction?.structuredFormat?.secondaryText?.text,
        })).filter((p: any) => p.placeId),
      });
    } catch (error: any) {
      console.error("[Places] Autocomplete failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  // Google Places API (New) - Get place details (address) by place ID
  app.get("/api/places/details/:placeId", async (req, res) => {
    const googleApiKey = process.env.GOOGLE_MAPS_API_KEY;
    if (!googleApiKey) {
      return res.status(400).json({ error: "Google Maps API key not configured", configured: false });
    }

    const { placeId } = req.params;
    if (!placeId) {
      return res.status(400).json({ error: "Place ID is required" });
    }

    try {
      console.log(`[Places] Getting details for: ${placeId}`);
      
      const response = await fetch(`https://places.googleapis.com/v1/places/${placeId}`, {
        method: "GET",
        headers: {
          "X-Goog-Api-Key": googleApiKey,
          "X-Goog-FieldMask": "displayName,formattedAddress,location,addressComponents",
        },
      });
      
      const data = await response.json();

      if (data.error) {
        console.error("[Places] Details error:", data.error.message);
        return res.status(500).json({ error: data.error.message });
      }

      return res.json({
        name: data.displayName?.text,
        formattedAddress: data.formattedAddress,
        location: data.location,
        addressComponents: data.addressComponents,
      });
    } catch (error: any) {
      console.error("[Places] Details failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  // Google Places API (New) - Find businesses at exact address
  app.get("/api/places/nearby", async (req, res) => {
    const googleApiKey = process.env.GOOGLE_MAPS_API_KEY;
    if (!googleApiKey) {
      return res.status(400).json({ error: "Google Maps API key not configured", configured: false });
    }

    const { lat, lng, address } = req.query;
    if (!lat || !lng || !address) {
      return res.status(400).json({ error: "Latitude, longitude, and address are required" });
    }

    try {
      console.log(`[Places] Finding businesses at: ${address} (${lat}, ${lng})`);
      
      const response = await fetch("https://places.googleapis.com/v1/places:searchNearby", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Goog-Api-Key": googleApiKey,
          "X-Goog-FieldMask": "places.displayName,places.formattedAddress,places.primaryType,places.types,places.id",
        },
        body: JSON.stringify({
          locationRestriction: {
            circle: {
              center: {
                latitude: parseFloat(lat as string),
                longitude: parseFloat(lng as string),
              },
              radius: 50.0,
            },
          },
          maxResultCount: 20,
        }),
      });
      
      const data = await response.json();

      if (data.error) {
        console.error("[Places] Nearby search error:", data.error.message);
        return res.status(500).json({ error: data.error.message });
      }

      const businesses = (data.places || []).map((p: any) => ({
        placeId: p.id,
        name: p.displayName?.text,
        address: p.formattedAddress,
        type: p.primaryType,
        types: p.types,
      }));

      console.log(`[Places] Found ${businesses.length} businesses at location`);
      return res.json({ businesses });
    } catch (error: any) {
      console.error("[Places] Nearby search failed:", error.message);
      return res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/github/status", async (_req, res) => {
    try {
      const status = await getSyncStatus();
      return res.json(status);
    } catch (error: any) {
      return res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/github/push", async (_req, res) => {
    try {
      console.log("[GitHub] Starting push to repository...");
      const result = await pushToGitHub();
      console.log("[GitHub] Push result:", result);
      return res.json(result);
    } catch (error: any) {
      console.error("[GitHub] Push failed:", error.message);
      return res.status(500).json({ success: false, error: error.message });
    }
  });

  app.post("/api/github/pull", async (_req, res) => {
    try {
      console.log("[GitHub] Starting pull from repository...");
      const result = await pullFromGitHub();
      console.log("[GitHub] Pull result:", result);
      return res.json(result);
    } catch (error: any) {
      console.error("[GitHub] Pull failed:", error.message);
      return res.status(500).json({ success: false, error: error.message });
    }
  });

  return httpServer;
}

interface RequestData {
  firstName?: string;
  lastName?: string;
  middleName?: string;
  ssn?: string;
  dateOfBirth?: string;
  street?: string;
  city?: string;
  state?: string;
  zip?: string;
  source?: "api" | "browser";
}

async function saveNormalizedReport(report: NormalizedCreditReport, ssn: string, rawEquifaxResponse?: any, requestData?: RequestData): Promise<FullCreditReport> {
  const cleanSsn = ssn.replace(/-/g, "");
  
  const currentEnv = equifaxClient.getActiveEnvironment();
  let consumer = await storage.getConsumerBySsnAndEnv(cleanSsn, currentEnv);
  
  if (consumer) {
    // Delete ALL existing data including new tables
    await Promise.all([
      storage.deleteAddressesByConsumerId(consumer.id),
      storage.deleteScoresByConsumerId(consumer.id),
      storage.deleteTradelinesByConsumerId(consumer.id),
      storage.deleteInquiriesByConsumerId(consumer.id),
      storage.deleteFraudAlertsByConsumerId(consumer.id),
      storage.deleteOfacAlertsByConsumerId(consumer.id),
      storage.deleteDataxTransactionByConsumerId(consumer.id),
      storage.deleteDataxIndicatorsByConsumerId(consumer.id),
      storage.deleteDataxSummaryByConsumerId(consumer.id),
    ]);
    
    consumer = await storage.updateConsumer(consumer.id, {
      firstName: report.consumer.firstName || report.consumer.name.split(" ")[0] || "",
      lastName: report.consumer.lastName || report.consumer.name.split(" ").slice(-1)[0] || "",
      middleName: report.consumer.middleName || report.consumer.name.split(" ").slice(1, -1).join(" ") || undefined,
      requestFirstName: requestData?.firstName || undefined,
      requestLastName: requestData?.lastName || undefined,
      requestMiddleName: requestData?.middleName || undefined,
      requestSsn: requestData?.ssn || undefined,
      requestDateOfBirth: requestData?.dateOfBirth || undefined,
      requestStreet: requestData?.street || undefined,
      requestCity: requestData?.city || undefined,
      requestState: requestData?.state || undefined,
      requestZip: requestData?.zip || undefined,
      dateOfBirth: report.consumer.dateOfBirth,
      reportDate: report.consumer.reportDate || new Date().toISOString().split("T")[0],
      fileSinceDate: report.consumer.fileSinceDate || undefined,
      lastActivityDate: report.consumer.lastActivityDate || undefined,
      hitCode: report.consumer.hitCode || undefined,
      hitCodeDescription: report.consumer.hitCodeDescription || undefined,
      customerNumber: report.consumer.customerNumber || undefined,
      ecoaInquiryType: report.consumer.ecoaInquiryType || undefined,
      environment: currentEnv,
      rawEquifaxResponse: rawEquifaxResponse || undefined,
      source: requestData?.source || "browser",
    }) || consumer;
  } else {
    consumer = await storage.createConsumer({
      ssn: cleanSsn,
      firstName: report.consumer.firstName || report.consumer.name.split(" ")[0] || "",
      lastName: report.consumer.lastName || report.consumer.name.split(" ").slice(-1)[0] || "",
      middleName: report.consumer.middleName || report.consumer.name.split(" ").slice(1, -1).join(" ") || undefined,
      requestFirstName: requestData?.firstName || undefined,
      requestLastName: requestData?.lastName || undefined,
      requestMiddleName: requestData?.middleName || undefined,
      requestSsn: requestData?.ssn || undefined,
      requestDateOfBirth: requestData?.dateOfBirth || undefined,
      requestStreet: requestData?.street || undefined,
      requestCity: requestData?.city || undefined,
      requestState: requestData?.state || undefined,
      requestZip: requestData?.zip || undefined,
      dateOfBirth: report.consumer.dateOfBirth,
      reportDate: report.consumer.reportDate || new Date().toISOString().split("T")[0],
      fileSinceDate: report.consumer.fileSinceDate || undefined,
      lastActivityDate: report.consumer.lastActivityDate || undefined,
      hitCode: report.consumer.hitCode || undefined,
      hitCodeDescription: report.consumer.hitCodeDescription || undefined,
      customerNumber: report.consumer.customerNumber || undefined,
      ecoaInquiryType: report.consumer.ecoaInquiryType || undefined,
      environment: currentEnv,
      rawEquifaxResponse: rawEquifaxResponse || undefined,
      source: requestData?.source || "browser",
    });
  }

  // Save ALL addresses with full details
  const savedAddresses = await Promise.all(
    (report.addresses || []).map((addr) =>
      storage.createAddress({
        consumerId: consumer.id,
        addressType: addr.identifier || "current",
        houseNumber: addr.houseNumber || undefined,
        streetName: addr.streetName || undefined,
        streetType: addr.streetType || undefined,
        apartmentNumber: addr.apartmentNumber || undefined,
        cityName: addr.cityName || undefined,
        stateAbbreviation: addr.stateAbbreviation || undefined,
        zipCode: addr.zipCode || undefined,
        rentOwnBuy: addr.rentOwnBuy || undefined,
        sourceOfAddressDescription: addr.sourceOfAddressDescription || undefined,
        dateFirstReported: addr.dateFirstReported || undefined,
        dateLastReported: addr.dateLastReported || undefined,
      })
    )
  );

  // Fallback: if no addresses were saved, parse from consumer.address string
  if (savedAddresses.length === 0 && report.consumer.address) {
    const addressParts = report.consumer.address.split(", ");
    if (addressParts.length >= 3) {
      const stateZip = addressParts[2].split(" ");
      await storage.createAddress({
        consumerId: consumer.id,
        addressType: "current",
        addressLine1: addressParts[0],
        cityName: addressParts[1],
        stateAbbreviation: stateZip[0],
        zipCode: stateZip[1],
      });
    }
  }

  // Save scores with ALL fields
  const savedScores = await Promise.all(
    report.scores.map(async (score) => {
      const savedScore = await storage.createCreditScore({
        consumerId: consumer.id,
        modelIdentifier: score.model,
        modelName: score.model,
        modelType: score.modelType || undefined,
        score: score.value,
        minScore: score.minScore || undefined,
        maxScore: score.maxScore || 850,
        riskBasedPricingLowRange: score.riskBasedPricingLowRange || undefined,
        riskBasedPricingHighRange: score.riskBasedPricingHighRange || undefined,
        riskBasedPricingPercentage: score.riskBasedPricingPercentage || undefined,
        rating: getScoreRating(score.value),
      });

      const savedFactors = await Promise.all(
        (score.factors || []).map((factor) =>
          storage.createScoreFactor({
            scoreId: savedScore.id,
            factorCode: factor.code,
            factorDescription: factor.description,
            rank: factor.rank || 1,
          })
        )
      );

      return { ...savedScore, factors: savedFactors };
    })
  );

  // Save tradelines with ALL fields including narratives and payment history
  const savedTradelines = await Promise.all(
    report.tradelines.map(async (tl: NormalizedTradeline) => {
      const savedTl = await storage.createTradeline({
        consumerId: consumer.id,
        customerNumber: tl.customerNumber || undefined,
        subscriberName: tl.creditorName,
        accountNumber: tl.accountNumber || undefined,
        accountTypeCode: tl.accountTypeCode || undefined,
        accountType: tl.accountType || undefined,
        accountDesignatorCode: tl.accountDesignatorCode || undefined,
        accountDesignatorDescription: tl.accountDesignatorDescription || undefined,
        portfolioTypeCode: tl.portfolioTypeCode || undefined,
        portfolioTypeDescription: tl.portfolioTypeDescription || undefined,
        activityDesignatorCode: tl.activityDesignatorCode || undefined,
        activityDesignatorDescription: tl.activityDesignatorDescription || undefined,
        currentBalance: tl.currentBalance,
        highCredit: tl.highCredit || undefined,
        creditLimit: tl.creditLimit || undefined,
        paymentAmount: tl.paymentAmount || undefined,
        actualPaymentAmount: tl.actualPaymentAmount || undefined,
        scheduledPaymentAmount: tl.scheduledPaymentAmount || undefined,
        pastDueAmount: tl.pastDueAmount || undefined,
        dateOpened: tl.dateOpened || undefined,
        dateClosed: tl.dateClosed || undefined,
        dateReported: tl.dateReported || undefined,
        dateLastPayment: tl.dateLastPayment || undefined,
        dateLastActivity: tl.dateLastActivity || undefined,
        dateMajorDelinquencyFirstReported: tl.dateMajorDelinquencyFirstReported || undefined,
        monthsReviewed: tl.monthsReviewed || undefined,
        thirtyDayCounter: tl.thirtyDayCounter || undefined,
        sixtyDayCounter: tl.sixtyDayCounter || undefined,
        ninetyDayCounter: tl.ninetyDayCounter || undefined,
        accountStatusCode: tl.accountStatusCode || undefined,
        accountStatusDescription: tl.accountStatus || undefined,
        rateCode: tl.rateCode || undefined,
        rateDescription: tl.rateDescription || undefined,
        termsFrequencyCode: tl.termsFrequencyCode || undefined,
        termsFrequencyDescription: tl.termsFrequencyDescription || undefined,
        termsDurationCode: tl.termsDurationCode || undefined,
        termsDurationDescription: tl.termsDurationDescription || undefined,
        previousHighRate1: tl.previousHighRate1 || undefined,
        previousHighDate1: tl.previousHighDate1 || undefined,
        previousHighRate2: tl.previousHighRate2 || undefined,
        previousHighDate2: tl.previousHighDate2 || undefined,
        previousHighRate3: tl.previousHighRate3 || undefined,
        previousHighDate3: tl.previousHighDate3 || undefined,
        automatedUpdateIndicator: tl.automatedUpdateIndicator || undefined,
        paymentHistory24: tl.paymentHistory24 || undefined,
      });

      // Save narrative codes
      const savedNarratives = await Promise.all(
        (tl.narrativeCodes || []).map((nc) =>
          storage.createTradelineNarrative({
            tradelineId: savedTl.id,
            narrativeCode: nc.code,
            narrativeDescription: nc.description || undefined,
          })
        )
      );

      // Save 24-month payment history
      const savedPaymentHistory = await Promise.all(
        (tl.paymentHistory || []).map((ph) =>
          storage.createTradelinePaymentHistory({
            tradelineId: savedTl.id,
            monthIndex: ph.monthIndex,
            statusCode: ph.statusCode || undefined,
            statusDescription: ph.statusDescription || undefined,
          })
        )
      );

      return { ...savedTl, narratives: savedNarratives, paymentHistory: savedPaymentHistory };
    })
  );

  // Save inquiries
  const savedInquiries = await Promise.all(
    report.inquiries.map((inq) =>
      storage.createInquiry({
        consumerId: consumer.id,
        inquiryType: inq.inquiryType || undefined,
        inquiryDate: inq.date,
        customerNumber: inq.customerNumber || undefined,
        customerName: inq.subscriber,
        industryCode: inq.industryCode || undefined,
        industryDescription: inq.industryDescription || undefined,
      })
    )
  );

  // Save fraud alerts
  const savedFraudAlerts = await Promise.all(
    (report.fraudAlerts || []).map((alert) =>
      storage.createFraudAlert({
        consumerId: consumer.id,
        alertTypeCode: alert.alertTypeCode || undefined,
        alertTypeDescription: alert.alertTypeDescription || undefined,
        dateReported: alert.dateReported || undefined,
        effectiveDate: alert.effectiveDate || undefined,
        contactPhones: alert.contactPhones || undefined,
      })
    )
  );

  // Save OFAC alerts
  const savedOfacAlerts = await Promise.all(
    (report.ofacAlerts || []).map((ofac) =>
      storage.createOfacAlert({
        consumerId: consumer.id,
        memberFirmCode: ofac.memberFirmCode || undefined,
        cdcResponseCode: ofac.cdcResponseCode || undefined,
        transactionType: ofac.transactionType || undefined,
        cdcTransactionDate: ofac.cdcTransactionDate || undefined,
        cdcTransactionTime: ofac.cdcTransactionTime || undefined,
        legalVerbiage: ofac.legalVerbiage || undefined,
        dataSegmentRegulated: ofac.dataSegmentRegulated || undefined,
        revisedLegalVerbiageIndicator: ofac.revisedLegalVerbiageIndicator || undefined,
      })
    )
  );

  // Save DataX transaction
  let savedDataxTransaction = null;
  if (report.dataxTransaction) {
    savedDataxTransaction = await storage.createDataxTransaction({
      consumerId: consumer.id,
      trackId: report.dataxTransaction.trackId || undefined,
      trackHash: report.dataxTransaction.trackHash || undefined,
      transactionId: report.dataxTransaction.transactionId || undefined,
      codeVersion: report.dataxTransaction.codeVersion || undefined,
      requestVersion: report.dataxTransaction.requestVersion || undefined,
      generationTime: report.dataxTransaction.generationTime || undefined,
      globalDecisionResult: report.dataxTransaction.globalDecisionResult || undefined,
      craBucket: report.dataxTransaction.craBucket || undefined,
    });
  }

  // Save DataX indicators
  const savedDataxIndicators = await Promise.all(
    (report.dataxIndicators || []).map((ind) =>
      storage.createDataxIndicator({
        consumerId: consumer.id,
        indicatorCode: ind.indicatorCode,
        indicatorCount: ind.indicatorCount || undefined,
        indicatorMessage: ind.indicatorMessage || undefined,
      })
    )
  );

  // Save DataX summary
  let savedDataxSummary = null;
  if (report.dataxSummary) {
    savedDataxSummary = await storage.createDataxSummary({
      consumerId: consumer.id,
      totalTradelines: report.dataxSummary.totalTradelines || undefined,
      currentTradelines: report.dataxSummary.currentTradelines || undefined,
      totalChargeOffs: report.dataxSummary.totalChargeOffs || undefined,
      totalRecoveries: report.dataxSummary.totalRecoveries || undefined,
      totalPaidOffs: report.dataxSummary.totalPaidOffs || undefined,
      firstPaymentDefaults: report.dataxSummary.firstPaymentDefaults || undefined,
      firstPaymentFatals: report.dataxSummary.firstPaymentFatals || undefined,
      daysSinceLastAch: report.dataxSummary.daysSinceLastAch || undefined,
      daysSinceLastReturn: report.dataxSummary.daysSinceLastReturn || undefined,
      daysSinceLastTradeline: report.dataxSummary.daysSinceLastTradeline || undefined,
      daysSinceLastFatalReturn: report.dataxSummary.daysSinceLastFatalReturn || undefined,
      lastPaymentDate: report.dataxSummary.lastPaymentDate || undefined,
      lastPaymentAmount: report.dataxSummary.lastPaymentAmount || undefined,
      lastPaymentType: report.dataxSummary.lastPaymentType || undefined,
      lastPaymentDisposition: report.dataxSummary.lastPaymentDisposition || undefined,
      lastReturnDate: report.dataxSummary.lastReturnDate || undefined,
      lastReturnReason: report.dataxSummary.lastReturnReason || undefined,
      lastReturnMessage: report.dataxSummary.lastReturnMessage || undefined,
      lastInquiryDate: report.dataxSummary.lastInquiryDate || undefined,
      lastTradelineDate: report.dataxSummary.lastTradelineDate || undefined,
      lastChargeOffDate: report.dataxSummary.lastChargeOffDate || undefined,
      lastThreePayments: report.dataxSummary.lastThreePayments || undefined,
      maximumOpenTradelines: report.dataxSummary.maximumOpenTradelines || undefined,
      maximumTotalPrincipal: report.dataxSummary.maximumTotalPrincipal || undefined,
      maximumTradelinePrincipal: report.dataxSummary.maximumTradelinePrincipal || undefined,
      totalCurrentPrincipal: report.dataxSummary.totalCurrentPrincipal || undefined,
      totalAchDebitAttempts: report.dataxSummary.totalAchDebitAttempts || undefined,
      totalUniqueMemberTradelines: report.dataxSummary.totalUniqueMemberTradelines || undefined,
      tradelinesByInquiringMember: report.dataxSummary.tradelinesByInquiringMember || undefined,
      addressDiscrepancyIndicator: report.dataxSummary.addressDiscrepancyIndicator || undefined,
      rawSummaryData: report.dataxSummary.rawSummaryData || undefined,
    });
  }

  const addresses = await storage.getAddressesByConsumerId(consumer.id);

  return {
    consumer,
    addresses,
    scores: savedScores,
    tradelines: savedTradelines,
    inquiries: savedInquiries,
    fraudAlerts: savedFraudAlerts,
    ofacAlerts: savedOfacAlerts,
    dataxTransaction: savedDataxTransaction,
    dataxIndicators: savedDataxIndicators,
    dataxSummary: savedDataxSummary,
  };
}

function formatFullReportForApi(report: FullCreditReport) {
  const { consumer, addresses, scores, tradelines, inquiries } = report;
  
  const primaryAddress = addresses[0];
  const addressStr = primaryAddress
    ? `${primaryAddress.addressLine1 || `${primaryAddress.houseNumber || ""} ${primaryAddress.streetName || ""} ${primaryAddress.streetType || ""}`.trim()}, ${primaryAddress.cityName}, ${primaryAddress.stateAbbreviation} ${primaryAddress.zipCode}`
    : "N/A";

  const queryName = consumer.requestFirstName || consumer.requestLastName
    ? `${consumer.requestFirstName || ""} ${consumer.requestLastName || ""}`.trim()
    : null;

  const equifaxName = `${consumer.firstName} ${consumer.middleName ? consumer.middleName + " " : ""}${consumer.lastName}`.trim();
  
  // Determine if Equifax returned a name different from the query
  // If the stored name exactly matches the query name (normalized), Equifax likely didn't return a name
  const queryNameNormalized = queryName?.toUpperCase().replace(/\s+/g, " ").trim();
  const equifaxNameNormalized = equifaxName.toUpperCase().replace(/\s+/g, " ").trim();
  const nameReturnedByEquifax = equifaxNameNormalized && equifaxNameNormalized !== queryNameNormalized;

  // Build query data object from stored request fields
  const queryData = {
    firstName: consumer.requestFirstName || null,
    lastName: consumer.requestLastName || null,
    ssn: consumer.requestSsn || consumer.ssn,
    dateOfBirth: consumer.requestDateOfBirth || null,
    address: {
      street: consumer.requestStreet || null,
      city: consumer.requestCity || null,
      state: consumer.requestState || null,
      zipCode: consumer.requestZip || null,
    },
  };

  return {
    id: consumer.id,
    personal: {
      name: equifaxName || queryName || "Unknown",
      queryName,
      equifaxName: nameReturnedByEquifax ? equifaxName : null,
      ssn: consumer.ssn,
      address: addressStr,
      dob: consumer.dateOfBirth || "N/A",
    },
    apiQuery: queryData,
    scores: scores.map((score) => ({
      provider: "Equifax" as const,
      score: score.score,
      maxScore: score.maxScore || 850,
      rating: score.rating || getScoreRating(score.score),
      updatedAt: score.createdAt.toISOString(),
      factors: score.factors.map((f) => ({
        code: f.factorCode,
        description: f.factorDescription,
        rank: f.rank,
      })),
    })),
    factors: generateFactorsFromNormalized(report),
    accounts: tradelines.map((tl, index) => ({
      id: tl.id,
      institution: tl.subscriberName || "Unknown",
      type: mapAccountType(tl.accountType || ""),
      balance: tl.currentBalance || 0,
      limit: tl.creditLimit,
      status: mapAccountStatus(tl.accountStatusCode || ""),
      openedAt: tl.dateOpened,
    })),
    inquiries: inquiries.length,
    rawEquifaxResponse: consumer.rawEquifaxResponse,
  };
}

function getScoreRating(score: number): "Poor" | "Fair" | "Good" | "Very Good" | "Excellent" {
  if (score >= 800) return "Excellent";
  if (score >= 740) return "Very Good";
  if (score >= 670) return "Good";
  if (score >= 580) return "Fair";
  return "Poor";
}

function mapAccountType(type: string): "Credit Card" | "Mortgage" | "Auto Loan" | "Personal Loan" {
  const typeUpper = (type || "").toUpperCase();
  if (typeUpper.includes("CREDIT") || typeUpper.includes("CC") || typeUpper === "R") return "Credit Card";
  if (typeUpper.includes("MORTGAGE") || typeUpper.includes("MT") || typeUpper === "M") return "Mortgage";
  if (typeUpper.includes("AUTO") || typeUpper.includes("AU") || typeUpper === "A") return "Auto Loan";
  return "Personal Loan";
}

function mapAccountStatus(status: string): "Current" | "Delinquent" | "Closed" {
  const statusUpper = (status || "").toUpperCase();
  if (statusUpper.includes("CURRENT") || statusUpper.includes("OPEN") || statusUpper === "C") return "Current";
  if (statusUpper.includes("CLOSED") || statusUpper === "T") return "Closed";
  return "Delinquent";
}

function generateFactorsFromNormalized(report: FullCreditReport): any[] {
  const factors = [];
  const { tradelines, inquiries, scores } = report;
  
  const totalBalance = tradelines.reduce((sum, tl) => sum + (tl.currentBalance || 0), 0);
  const totalLimit = tradelines.reduce((sum, tl) => sum + (tl.creditLimit || 0), 0);
  const utilization = totalLimit > 0 ? Math.round((totalBalance / totalLimit) * 100) : 0;
  
  const delinquentCount = tradelines.filter(tl => 
    mapAccountStatus(tl.accountStatusCode || "") === "Delinquent"
  ).length;
  const paymentRate = tradelines.length > 0 
    ? Math.round(((tradelines.length - delinquentCount) / tradelines.length) * 100)
    : 100;
  
  factors.push({
    name: "Payment History",
    impact: "High" as const,
    status: paymentRate >= 95 ? "Excellent" : paymentRate >= 80 ? "Good" : "Fair",
    value: `${paymentRate}%`,
    description: "Percentage of payments made on time",
  });
  
  factors.push({
    name: "Credit Usage",
    impact: "High" as const,
    status: utilization <= 10 ? "Excellent" : utilization <= 30 ? "Good" : utilization <= 50 ? "Fair" : "Poor",
    value: `${utilization}%`,
    description: "Credit utilized vs available limit",
  });
  
  factors.push({
    name: "Hard Inquiries",
    impact: "Low" as const,
    status: inquiries.length <= 1 ? "Excellent" : inquiries.length <= 3 ? "Good" : "Fair",
    value: inquiries.length.toString(),
    description: "Inquiries in the last 2 years",
  });
  
  factors.push({
    name: "Total Accounts",
    impact: "Low" as const,
    status: tradelines.length >= 5 ? "Good" : "Fair",
    value: tradelines.length.toString(),
    description: "Total open and closed accounts",
  });

  if (scores[0]?.factors) {
    scores[0].factors.slice(0, 2).forEach((factor, idx) => {
      if (factor.factorDescription) {
        factors.push({
          name: `Risk Factor ${idx + 1}`,
          impact: "Medium" as const,
          status: "Fair",
          value: factor.factorCode || "-",
          description: factor.factorDescription,
        });
      }
    });
  }
  
  return factors;
}
