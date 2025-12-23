export interface CreditScore {
  provider: "Equifax" | "TransUnion" | "Experian";
  score: number;
  maxScore: number;
  rating: "Poor" | "Fair" | "Good" | "Very Good" | "Excellent";
  updatedAt: string;
}

export interface CreditFactor {
  name: string;
  impact: "High" | "Medium" | "Low";
  status: "Excellent" | "Good" | "Fair" | "Poor";
  value: string;
  description: string;
}

export interface Account {
  id: string;
  institution: string;
  type: "Credit Card" | "Mortgage" | "Auto Loan" | "Personal Loan";
  balance: number;
  limit?: number;
  status: "Current" | "Delinquent" | "Closed";
  openedAt: string;
}

export interface PersonalInfo {
  name: string;
  queryName: string | null;
  equifaxName: string | null;
  ssn: string;
  address: string;
  dob: string;
}

export interface CreditReportData {
  id: string;
  personal: PersonalInfo;
  scores: CreditScore[];
  factors: CreditFactor[];
  accounts: Account[];
  inquiries: number;
  source?: "equifax" | "cache";
  pulledAt?: string;
  cachedAt?: string;
  rawEquifaxRequest?: any;
  rawEquifaxResponse?: any;
  pdfPath?: string;
}

export interface CreditReportRequest {
  firstName: string;
  lastName: string;
  ssn: string;
  dateOfBirth: string;
  address: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
  };
}

export interface PrescreenRequest extends CreditReportRequest {
  minScoreThreshold?: number;
}

export interface PrescreenResult {
  decision: "APPROVED" | "DECLINED" | "REFER";
  scoreUsed: number;
  scoreModel: string;
  riskIndicators: string[];
  pullType: "soft";
  processedAt: string;
  rawEquifaxRequest?: any;
  rawEquifaxResponse?: any;
}

export interface PQOScoreModel {
  type: string;
  modelNumber: string;
  score?: number;
  reasons?: Array<{ code: string; description?: string }>;
  riskBasedPricing?: {
    percentage: string;
    lowRange: string;
    highRange: string;
  };
}

export interface PQOAddress {
  addressType: string;
  addressLine1: string;
  city: string;
  state: string;
  zipCode: string;
  dateFirstReported?: string;
  dateLastReported?: string;
}

export interface PQOFraudIndicator {
  code: string;
  description: string;
}

export interface PQOResult {
  decision: "APPROVED" | "DECLINED" | "REFER" | "ERROR";
  scoreUsed?: number;
  scoreModel?: string;
  models?: PQOScoreModel[];
  addresses?: PQOAddress[];
  fraudIndicator?: PQOFraudIndicator;
  offers?: Array<{
    offerCode?: string;
    description?: string;
    terms?: string;
  }>;
  riskIndicators?: string[];
  message?: string;
  pullType: "soft";
  processedAt: string;
  requestUrl?: string;
  requestHeaders?: Record<string, string>;
  rawEquifaxRequest?: any;
  rawEquifaxResponse?: any;
}

export interface EquifaxStatus {
  configured: boolean;
  pqoConfigured?: boolean;
  environment: string;
}

export type EquifaxEnvironment = "sandbox" | "test" | "production";

export interface EnvironmentConfig {
  name: EquifaxEnvironment;
  displayName: string;
  baseUrl: string;
  configured: boolean;
  missingSecrets: string[];
}

export interface EnvironmentsResponse {
  environments: EnvironmentConfig[];
  active: EquifaxEnvironment;
}

export async function getEnvironments(): Promise<EnvironmentsResponse> {
  const response = await fetch("/api/equifax/environments");
  if (!response.ok) {
    throw new Error("Failed to fetch environments");
  }
  return response.json();
}

export async function switchEnvironment(environment: EquifaxEnvironment, confirmProduction?: string): Promise<{ success: boolean; active: EquifaxEnvironment; baseUrl: string }> {
  const response = await fetch("/api/equifax/environment", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ environment, confirmProduction }),
  });
  
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to switch environment", errorJson);
  }
  return response.json();
}

export interface TokenRefreshResult {
  success: boolean;
  environment: string;
  token: string;
  expiresIn: number;
}

export async function refreshToken(): Promise<TokenRefreshResult> {
  const response = await fetch("/api/equifax/refresh-token", {
    method: "POST",
  });
  
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to refresh token", errorJson);
  }
  return response.json();
}

export interface RefetchReportResult {
  success: boolean;
  consumer: {
    name: string;
    ssnLast4: string;
    address: string;
    dateOfBirth: string;
  };
  scores: Array<{
    model: string;
    value: number;
    factors: Array<{ code: string; description: string }>;
  }>;
  tradelines: Array<{
    creditorName: string;
    accountType: string;
    currentBalance: number;
    creditLimit?: number;
    accountStatus: string;
    dateOpened: string;
  }>;
  inquiries: Array<{
    date: string;
    subscriber: string;
    type: string;
  }>;
  pdfPath?: string;
  rawEquifaxResponse: any;
  refetchedAt: string;
}

export async function refetchReportByPath(reportPath: string): Promise<RefetchReportResult> {
  const response = await fetch(`/api/equifax/refetch?path=${encodeURIComponent(reportPath)}`);
  
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to re-fetch report", errorJson);
  }
  return response.json();
}

export interface ConsumerSummary {
  id: string;
  name: string;
  equifaxName: string | null;
  ssn: string;
  dateOfBirth: string | null;
  primaryScore: number | null;
  scoreRating: string | null;
  tradelineCount: number;
  inquiryCount: number;
  hitCodeDescription: string | null;
  environment: string | null;
  pdfStoragePath: string | null;
  pdfImageStoragePath: string | null;
  reportDate: string | null;
  source: string | null;
  createdAt: string;
}

// Check if Equifax API is configured
export async function checkEquifaxStatus(): Promise<EquifaxStatus> {
  const response = await fetch("/api/equifax/status");
  if (!response.ok) {
    throw new Error("Failed to check Equifax status");
  }
  return response.json();
}

// Get all consumers that have been tested
export async function getConsumers(): Promise<ConsumerSummary[]> {
  const response = await fetch("/api/consumers");
  if (!response.ok) {
    throw new Error("Failed to fetch consumers");
  }
  return response.json();
}

// Delete a consumer by ID
export async function deleteConsumer(id: string): Promise<void> {
  const response = await fetch(`/api/consumers/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error("Failed to delete consumer");
  }
}

// Update consumer query data
export async function updateConsumerQueryData(id: string, queryData: {
  firstName?: string;
  lastName?: string;
  middleName?: string;
  ssn?: string;
  dateOfBirth?: string;
  address?: {
    street?: string;
    city?: string;
    state?: string;
    zipCode?: string;
  };
}): Promise<void> {
  const response = await fetch(`/api/consumers/${encodeURIComponent(id)}/query`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(queryData),
  });
  if (!response.ok) {
    throw new Error("Failed to update query data");
  }
}

export interface ReparseResult {
  success: boolean;
  message: string;
  summary: {
    scores: number;
    tradelines: number;
    inquiries: number;
  };
}

// Reparse raw Equifax JSON for a consumer
export async function reparseConsumer(id: string): Promise<ReparseResult> {
  const response = await fetch(`/api/consumers/${encodeURIComponent(id)}/reparse`, {
    method: "POST",
  });
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to reparse consumer", errorJson);
  }
  return response.json();
}

export class ApiError extends Error {
  constructor(message: string, public rawJson: any) {
    super(message);
    this.name = "ApiError";
  }
}

// Pull a fresh credit report from Equifax (HARD PULL)
export async function pullCreditReport(request: CreditReportRequest): Promise<CreditReportData> {
  const response = await fetch("/api/equifax/credit-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to pull credit report", errorJson);
  }
  
  return response.json();
}

// Perform a prescreen / soft pull
export async function performPrescreen(request: PrescreenRequest): Promise<PrescreenResult> {
  const response = await fetch("/api/equifax/prescreen", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to perform prescreen", errorJson);
  }
  
  return response.json();
}

// Perform a Prequalification of One (PQO) / soft pull
export async function performPQO(request: CreditReportRequest): Promise<PQOResult> {
  const response = await fetch("/api/equifax/pqo", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  
  if (!response.ok) {
    const errorJson = await response.json();
    throw new ApiError(errorJson.error || "Failed to perform prequalification", errorJson);
  }
  
  return response.json();
}

// Get cached credit report by SSN
export async function getCachedReport(ssn: string): Promise<CreditReportData | null> {
  const response = await fetch(`/api/reports/${encodeURIComponent(ssn)}`);
  
  if (response.status === 404) {
    return null;
  }
  
  if (!response.ok) {
    throw new Error("Failed to fetch cached report");
  }
  
  return response.json();
}

// Get cached credit report by customer ID
export async function getCachedReportById(id: string): Promise<CreditReportData | null> {
  const response = await fetch(`/api/reports/id/${encodeURIComponent(id)}`);
  
  if (response.status === 404) {
    return null;
  }
  
  if (!response.ok) {
    throw new Error("Failed to fetch cached report");
  }
  
  return response.json();
}

// Legacy: fetch report (uses mock if not found)
export async function fetchCreditReport(ssn: string): Promise<CreditReportData> {
  const response = await fetch(`/api/reports/${ssn}`);
  
  if (response.status === 404) {
    const mockData = generateMockData(ssn);
    await saveCreditReport(mockData);
    return mockData;
  }
  
  if (!response.ok) {
    throw new Error("Failed to fetch credit report");
  }
  
  return response.json();
}

export async function saveCreditReport(data: CreditReportData): Promise<CreditReportData> {
  const response = await fetch("/api/reports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ssn: data.personal.ssn,
      personalInfo: data.personal,
      scores: data.scores,
      factors: data.factors,
      accounts: data.accounts,
      inquiries: data.inquiries,
    }),
  });
  
  if (!response.ok) {
    throw new Error("Failed to save credit report");
  }
  
  return response.json();
}

function generateMockData(ssn: string): CreditReportData {
  const last4 = ssn.slice(-4);
  
  return {
    id: `mock-${ssn}`,
    personal: {
      name: "Alex J. Mercer",
      queryName: null,
      equifaxName: null,
      ssn: `***-**-${last4}`,
      address: "123 Financial District, New York, NY 10005",
      dob: "1985-04-12",
    },
    scores: [
      {
        provider: "Equifax",
        score: 742,
        maxScore: 850,
        rating: "Very Good",
        updatedAt: new Date().toISOString(),
      },
    ],
    factors: [
      {
        name: "Payment History",
        impact: "High",
        status: "Excellent",
        value: "100%",
        description: "Percentage of payments made on time",
      },
      {
        name: "Credit Usage",
        impact: "High",
        status: "Good",
        value: "12%",
        description: "Credit utilized vs available limit",
      },
      {
        name: "Credit Age",
        impact: "Medium",
        status: "Fair",
        value: "4.2 yrs",
        description: "Average age of open accounts",
      },
      {
        name: "Total Accounts",
        impact: "Low",
        status: "Good",
        value: "12",
        description: "Total open and closed accounts",
      },
      {
        name: "Hard Inquiries",
        impact: "Low",
        status: "Excellent",
        value: "1",
        description: "Inquiries in the last 2 years",
      },
    ],
    accounts: [
      {
        id: "acc_1",
        institution: "Chase Sapphire",
        type: "Credit Card",
        balance: 1240.50,
        limit: 15000,
        status: "Current",
        openedAt: "2019-03-15",
      },
      {
        id: "acc_2",
        institution: "Wells Fargo Mortgage",
        type: "Mortgage",
        balance: 342000,
        status: "Current",
        openedAt: "2020-08-01",
      },
      {
        id: "acc_3",
        institution: "Ally Auto",
        type: "Auto Loan",
        balance: 12500,
        status: "Current",
        openedAt: "2021-11-20",
      },
    ],
    inquiries: 1,
    source: "cache",
  };
}

export interface StorageReport {
  name: string;
  objectPath: string;
  metadata: {
    consumerName?: string;
    ssnLast4?: string;
    environment?: string;
    uploadedAt?: string;
  };
  size: number;
  created: string;
}

export interface StorageStatus {
  configured: boolean;
  directory: string;
  autoUploadEnabled: boolean;
  environment: string;
}

export async function getStorageStatus(): Promise<StorageStatus> {
  const response = await fetch("/api/storage/status");
  if (!response.ok) {
    throw new Error("Failed to fetch storage status");
  }
  return response.json();
}

export async function getStorageReports(environment?: string): Promise<{ success: boolean; count: number; reports: StorageReport[] }> {
  const url = environment ? `/api/storage/reports?environment=${environment}` : "/api/storage/reports";
  const response = await fetch(url);
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || "Failed to fetch storage reports");
  }
  return response.json();
}

export function findStorageReportForConsumer(reports: StorageReport[], ssnLast4: string): StorageReport | null {
  return reports.find(r => r.metadata?.ssnLast4 === ssnLast4 || r.name.includes(`_${ssnLast4}_`)) || null;
}

export interface PdfPage {
  pageNumber: number;
  dataUrl: string;
  width: number;
  height: number;
}

export interface PdfImagesResult {
  success: boolean;
  pageCount: number;
  pages: PdfPage[];
  error?: string;
}

export async function getPdfImages(pdfPath: string): Promise<PdfImagesResult> {
  // Remove /objects/ prefix if present
  let path = pdfPath.startsWith('/objects/') ? pdfPath.replace('/objects/', '') : pdfPath;
  
  // Security: Basic path validation and sanitization
  if (path.includes("..") || path.includes("//")) {
    throw new Error("Invalid PDF path");
  }
  
  // Encode path segments properly
  const encodedPath = path.split('/').map(segment => encodeURIComponent(segment)).join('/');
  
  const response = await fetch(`/api/pdf-images/${encodedPath}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to load PDF images" }));
    throw new Error(errorData.error || "Failed to load PDF images");
  }
  return response.json();
}

export async function getStoredPdfImages(storedImagePath: string): Promise<PdfImagesResult> {
  // Remove /objects/ prefix if present
  let path = storedImagePath.startsWith('/objects/') ? storedImagePath.replace('/objects/', '') : storedImagePath;
  
  // Security: Basic path validation and sanitization
  if (path.includes("..") || path.includes("//")) {
    throw new Error("Invalid image path");
  }
  
  // Encode path segments properly
  const encodedPath = path.split('/').map(segment => encodeURIComponent(segment)).join('/');
  
  const response = await fetch(`/api/stored-pdf-images/${encodedPath}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to load stored images" }));
    throw new Error(errorData.error || "Failed to load stored images");
  }
  return response.json();
}

export interface RegenerateImagesResult {
  success: boolean;
  message?: string;
  pdfImageStoragePath?: string;
  pageCount?: number;
  skipped?: boolean;
  error?: string;
}

export async function regeneratePdfImages(consumerId: string): Promise<RegenerateImagesResult> {
  const response = await fetch(`/api/consumers/${consumerId}/regenerate-images`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to regenerate images" }));
    return { success: false, error: errorData.error || "Failed to regenerate images" };
  }
  return response.json();
}

// IP Whitelist types and API functions
export interface WhitelistedIp {
  id: string;
  ipAddress: string;
  description: string | null;
  isEnabled: boolean;
  createdAt: string;
}

export interface CreateWhitelistedIpRequest {
  ipAddress: string;
  description?: string;
  isEnabled?: boolean;
}

export interface UpdateWhitelistedIpRequest {
  ipAddress?: string;
  description?: string;
  isEnabled?: boolean;
}

export async function getWhitelistedIps(): Promise<WhitelistedIp[]> {
  const response = await fetch("/api/settings/ip-whitelist");
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to fetch IP whitelist" }));
    throw new Error(errorData.error || "Failed to fetch IP whitelist");
  }
  return response.json();
}

export async function createWhitelistedIp(data: CreateWhitelistedIpRequest): Promise<WhitelistedIp> {
  const response = await fetch("/api/settings/ip-whitelist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to add IP" }));
    throw new Error(errorData.error || "Failed to add IP");
  }
  return response.json();
}

export async function updateWhitelistedIp(id: string, data: UpdateWhitelistedIpRequest): Promise<WhitelistedIp> {
  const response = await fetch(`/api/settings/ip-whitelist/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to update IP" }));
    throw new Error(errorData.error || "Failed to update IP");
  }
  return response.json();
}

export async function deleteWhitelistedIp(id: string): Promise<void> {
  const response = await fetch(`/api/settings/ip-whitelist/${id}`, {
    method: "DELETE",
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to delete IP" }));
    throw new Error(errorData.error || "Failed to delete IP");
  }
}

// API Client types and functions for third-party OAuth access
export interface ApiClient {
  id: string;
  name: string;
  clientId: string;
  clientSecret: string | null;
  isEnabled: boolean;
  lastUsedAt: string | null;
  createdAt: string;
}

export interface CreateApiClientResponse {
  id: string;
  name: string;
  clientId: string;
  clientSecret: string;
  isEnabled: boolean;
  createdAt: string;
}

export interface RotateSecretResponse {
  id: string;
  clientId: string;
  clientSecret: string;
}

export interface ApiRequestLog {
  id: string;
  clientId: string;
  clientName?: string;
  endpoint: string;
  method: string;
  statusCode: number | null;
  durationMs: number | null;
  requestBody: any;
  responseBody: any;
  errorMessage: string | null;
  ipAddress: string | null;
  createdAt: string;
}

export async function getApiClients(): Promise<ApiClient[]> {
  const response = await fetch("/api/admin/clients");
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to fetch API clients" }));
    throw new Error(errorData.error || "Failed to fetch API clients");
  }
  return response.json();
}

export async function createApiClient(name: string): Promise<CreateApiClientResponse> {
  const response = await fetch("/api/admin/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to create API client" }));
    throw new Error(errorData.error || "Failed to create API client");
  }
  return response.json();
}

export async function updateApiClient(id: string, data: { name?: string; isEnabled?: boolean }): Promise<ApiClient> {
  const response = await fetch(`/api/admin/clients/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to update API client" }));
    throw new Error(errorData.error || "Failed to update API client");
  }
  return response.json();
}

export async function rotateApiClientSecret(id: string): Promise<RotateSecretResponse> {
  const response = await fetch(`/api/admin/clients/${id}/rotate-secret`, {
    method: "POST",
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to rotate secret" }));
    throw new Error(errorData.error || "Failed to rotate secret");
  }
  return response.json();
}

export async function deleteApiClient(id: string): Promise<void> {
  const response = await fetch(`/api/admin/clients/${id}`, {
    method: "DELETE",
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to delete API client" }));
    throw new Error(errorData.error || "Failed to delete API client");
  }
}

export async function getApiRequestLogs(limit?: number): Promise<ApiRequestLog[]> {
  const url = limit ? `/api/admin/request-logs?limit=${limit}` : "/api/admin/request-logs";
  const response = await fetch(url);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: "Failed to fetch request logs" }));
    throw new Error(errorData.error || "Failed to fetch request logs");
  }
  return response.json();
}
