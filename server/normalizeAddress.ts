export interface UspsCorrection {
  code: string;
  text: string;
}

export interface MatchError {
  source: "usps" | "census" | "google";
  code: string;
  message: string;
}

export interface NormalizedAddress {
  streetNumber: string;
  streetDirection: string;
  streetName: string;
  streetType: string;
  unitNumber: string;
  city: string;
  county: string;
  state: string;
  zipCode: string;
  zip4: string;
  country: string;
  formattedAddress: string;
  coordinates: {
    latitude: number | null;
    longitude: number | null;
  };
  corrections: UspsCorrection[];
  sources: {
    streetNumber: "google" | "usps" | "census" | null;
    city: "usps" | "google" | "census" | null;
    state: "usps" | "google" | "census" | null;
    zipCode: "usps" | "google" | null;
    county: "google" | "census" | null;
    coordinates: "google" | "census" | null;
  };
  matchQuality: "full" | "partial" | "failed";
  errors: MatchError[];
  warnings: string[];
}

export interface GeocodingResult {
  google?: {
    matched?: boolean;
    partialMatch?: boolean;
    error?: boolean;
    message?: string;
    raw?: {
      results?: Array<{
        address_components?: Array<{
          long_name: string;
          short_name: string;
          types: string[];
        }>;
        formatted_address?: string;
        partial_match?: boolean;
        geometry?: {
          location?: {
            lat: number;
            lng: number;
          };
        };
      }>;
    };
    city?: string;
    county?: string;
    state?: string;
    zipCode?: string;
    formattedAddress?: string;
    coordinates?: {
      latitude?: number;
      longitude?: number;
    };
  } | null;
  usps?: {
    matched?: boolean;
    error?: boolean;
    message?: string;
    city?: string;
    state?: string;
    zip5?: string;
    zip4?: string;
    address2?: string;
    corrections?: Array<{
      code: string;
      text: string;
    }>;
  } | null;
  census?: {
    matched?: boolean;
    error?: boolean;
    message?: string;
    matchedAddress?: string;
    county?: string;
    state?: string;
    coordinates?: {
      latitude?: number;
      longitude?: number;
    };
  } | null;
}

const STREET_TYPES = [
  "Street", "St", "Avenue", "Ave", "Boulevard", "Blvd", "Road", "Rd",
  "Drive", "Dr", "Lane", "Ln", "Way", "Court", "Ct", "Circle", "Cir",
  "Place", "Pl", "Terrace", "Ter", "Trail", "Trl", "Parkway", "Pkwy",
  "Highway", "Hwy", "Loop", "Alley", "Aly", "Pass", "Path", "Pike",
  "Run", "Square", "Sq", "Walk", "Crossing", "Xing"
];

const DIRECTIONS = [
  "N", "S", "E", "W", "NE", "NW", "SE", "SW",
  "North", "South", "East", "West",
  "Northeast", "Northwest", "Southeast", "Southwest"
];

export function normalizeAddress(geoResult: GeocodingResult): NormalizedAddress {
  const raw = geoResult.google?.raw?.results?.[0]?.address_components;
  const uspsMatched = geoResult.usps?.matched === true;
  
  const getGoogleComponent = (type: string): string => {
    if (!raw) return "";
    const component = raw.find((c) => c.types.includes(type));
    return component?.long_name || "";
  };

  const getGoogleCity = (): string => {
    if (!raw) return "";
    const cityTypes = ["locality", "postal_town", "sublocality_level_1", "sublocality", "administrative_area_level_3"];
    for (const type of cityTypes) {
      const val = raw.find((c) => c.types.includes(type))?.long_name;
      if (val) return val;
    }
    return "";
  };

  const streetNumber = getGoogleComponent("street_number");
  const route = getGoogleComponent("route");
  const subpremise = getGoogleComponent("subpremise");

  let streetDirection = "";
  let streetName = route;
  let streetType = "";

  if (route) {
    const words = route.split(" ");
    
    if (words.length > 0 && DIRECTIONS.some(d => d.toLowerCase() === words[0].toLowerCase())) {
      streetDirection = words[0];
      words.shift();
    }
    
    if (words.length > 0 && STREET_TYPES.some(t => t.toLowerCase() === words[words.length - 1].toLowerCase())) {
      streetType = words.pop() || "";
    }
    
    streetName = words.join(" ");
  }

  const city = uspsMatched && geoResult.usps?.city
    ? geoResult.usps.city
    : (geoResult.google?.city || getGoogleCity());

  const state = uspsMatched && geoResult.usps?.state
    ? geoResult.usps.state
    : (geoResult.google?.state || geoResult.census?.state || "");

  const zipCode = uspsMatched && geoResult.usps?.zip5
    ? geoResult.usps.zip5
    : (geoResult.google?.zipCode || "");

  const zip4 = geoResult.usps?.zip4 || "";

  const county = geoResult.google?.county || geoResult.census?.county || "";

  const country = getGoogleComponent("country") || "USA";

  let coordinates: { latitude: number | null; longitude: number | null } = {
    latitude: null,
    longitude: null,
  };
  let coordinatesSource: "google" | "census" | null = null;

  if (geoResult.google?.coordinates?.latitude && geoResult.google?.coordinates?.longitude) {
    coordinates = {
      latitude: geoResult.google.coordinates.latitude,
      longitude: geoResult.google.coordinates.longitude,
    };
    coordinatesSource = "google";
  } else if (geoResult.census?.coordinates?.latitude && geoResult.census?.coordinates?.longitude) {
    coordinates = {
      latitude: geoResult.census.coordinates.latitude,
      longitude: geoResult.census.coordinates.longitude,
    };
    coordinatesSource = "census";
  }

  const standardizedAddress = geoResult.usps?.address2 || "";
  const formattedAddress = uspsMatched && standardizedAddress
    ? `${standardizedAddress}, ${city}, ${state} ${zipCode}${zip4 ? `-${zip4}` : ""}`
    : (geoResult.google?.formattedAddress || geoResult.census?.matchedAddress || "");

  const corrections: UspsCorrection[] = (geoResult.usps?.corrections || []).map(c => ({
    code: c.code || "",
    text: c.text || "",
  }));

  // Check for partial match from Google raw response
  const googlePartialMatch = geoResult.google?.partialMatch === true || 
    geoResult.google?.raw?.results?.[0]?.partial_match === true;

  // Build errors array
  const errors: MatchError[] = [];
  
  if (geoResult.usps?.error || geoResult.usps?.matched === false) {
    errors.push({
      source: "usps",
      code: "NO_MATCH",
      message: geoResult.usps?.message || "USPS could not validate this address"
    });
  }
  
  if (geoResult.census?.error || geoResult.census?.matched === false) {
    errors.push({
      source: "census",
      code: "NO_MATCH", 
      message: geoResult.census?.message || "Census Bureau could not geocode this address"
    });
  }
  
  if (geoResult.google?.error || geoResult.google?.matched === false) {
    errors.push({
      source: "google",
      code: "NO_MATCH",
      message: geoResult.google?.message || "Google Maps could not find this address"
    });
  }

  // Build warnings array
  const warnings: string[] = [];
  
  if (googlePartialMatch) {
    warnings.push("Google Maps returned a partial match - address may be incomplete or ambiguous");
  }
  
  if (!streetNumber && geoResult.google?.matched) {
    warnings.push("Street number could not be parsed from the address");
  }
  
  if (!zipCode) {
    warnings.push("ZIP code could not be determined");
  }

  // Determine match quality
  let matchQuality: "full" | "partial" | "failed" = "failed";
  
  const uspsSuccess = geoResult.usps?.matched === true;
  const censusSuccess = geoResult.census?.matched === true;
  const googleSuccess = geoResult.google?.matched === true && !googlePartialMatch;
  
  if (uspsSuccess && censusSuccess && googleSuccess) {
    matchQuality = "full";
  } else if (uspsSuccess || censusSuccess || (geoResult.google?.matched && !googlePartialMatch)) {
    matchQuality = "partial";
  } else if (geoResult.google?.matched && googlePartialMatch) {
    matchQuality = "partial";
  }

  return {
    streetNumber,
    streetDirection,
    streetName,
    streetType,
    unitNumber: subpremise,
    city,
    county,
    state,
    zipCode,
    zip4,
    country,
    formattedAddress,
    coordinates,
    corrections,
    sources: {
      streetNumber: streetNumber ? "google" : null,
      city: uspsMatched && geoResult.usps?.city ? "usps" : (geoResult.google?.city || getGoogleCity() ? "google" : (geoResult.census?.state ? "census" : null)),
      state: uspsMatched && geoResult.usps?.state ? "usps" : (geoResult.google?.state ? "google" : (geoResult.census?.state ? "census" : null)),
      zipCode: uspsMatched && geoResult.usps?.zip5 ? "usps" : (geoResult.google?.zipCode ? "google" : null),
      county: geoResult.google?.county ? "google" : (geoResult.census?.county ? "census" : null),
      coordinates: coordinatesSource,
    },
    matchQuality,
    errors,
    warnings,
  };
}
