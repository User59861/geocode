import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, date, decimal, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const consumers = pgTable("consumers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  ssn: text("ssn").notNull(),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  middleName: text("middle_name"),
  requestFirstName: text("request_first_name"),
  requestLastName: text("request_last_name"),
  requestMiddleName: text("request_middle_name"),
  requestSsn: text("request_ssn"),
  requestDateOfBirth: text("request_date_of_birth"),
  requestStreet: text("request_street"),
  requestCity: text("request_city"),
  requestState: text("request_state"),
  requestZip: text("request_zip"),
  dateOfBirth: text("date_of_birth"),
  fileSinceDate: text("file_since_date"),
  lastActivityDate: text("last_activity_date"),
  reportDate: text("report_date"),
  consumerReferralCode: text("consumer_referral_code"),
  environment: text("environment"),
  hitCode: text("hit_code"),
  hitCodeDescription: text("hit_code_description"),
  customerNumber: text("customer_number"),
  ecoaInquiryType: text("ecoa_inquiry_type"),
  rawEquifaxResponse: jsonb("raw_equifax_response"),
  pdfStoragePath: text("pdf_storage_path"),
  pdfImageStoragePath: text("pdf_image_storage_path"),
  source: text("source").default("browser"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const consumerAddresses = pgTable("consumer_addresses", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  addressType: text("address_type").notNull(),
  houseNumber: text("house_number"),
  streetName: text("street_name"),
  streetType: text("street_type"),
  apartmentNumber: text("apartment_number"),
  cityName: text("city_name"),
  stateAbbreviation: text("state_abbreviation"),
  zipCode: text("zip_code"),
  addressLine1: text("address_line_1"),
  rentOwnBuy: text("rent_own_buy"),
  sourceOfAddressCode: text("source_of_address_code"),
  sourceOfAddressDescription: text("source_of_address_description"),
  dateFirstReported: text("date_first_reported"),
  dateLastReported: text("date_last_reported"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const creditScores = pgTable("credit_scores", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  modelType: text("model_type"),
  modelIdentifier: text("model_identifier").notNull(),
  modelName: text("model_name"),
  score: integer("score").notNull(),
  maxScore: integer("max_score").default(850),
  minScore: integer("min_score").default(300),
  rating: text("rating"),
  riskBasedPricingLowRange: integer("rbp_low_range"),
  riskBasedPricingHighRange: integer("rbp_high_range"),
  riskBasedPricingPercentage: integer("rbp_percentage"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const scoreFactors = pgTable("score_factors", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scoreId: varchar("score_id").notNull().references(() => creditScores.id, { onDelete: "cascade" }),
  factorCode: text("factor_code").notNull(),
  factorDescription: text("factor_description"),
  rank: integer("rank"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const tradelines = pgTable("tradelines", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  customerNumber: text("customer_number"),
  subscriberName: text("subscriber_name"),
  accountNumber: text("account_number"),
  accountTypeCode: text("account_type_code"),
  accountType: text("account_type"),
  accountDesignatorCode: text("account_designator_code"),
  accountDesignatorDescription: text("account_designator_description"),
  portfolioTypeCode: text("portfolio_type_code"),
  portfolioTypeDescription: text("portfolio_type_description"),
  activityDesignatorCode: text("activity_designator_code"),
  activityDesignatorDescription: text("activity_designator_description"),
  currentBalance: integer("current_balance").default(0),
  highCredit: integer("high_credit"),
  creditLimit: integer("credit_limit"),
  paymentAmount: integer("payment_amount"),
  actualPaymentAmount: integer("actual_payment_amount"),
  scheduledPaymentAmount: integer("scheduled_payment_amount"),
  pastDueAmount: integer("past_due_amount"),
  dateOpened: text("date_opened"),
  dateClosed: text("date_closed"),
  dateReported: text("date_reported"),
  dateLastPayment: text("date_last_payment"),
  dateLastActivity: text("date_last_activity"),
  dateMajorDelinquencyFirstReported: text("date_major_delinquency_first_reported"),
  monthsReviewed: integer("months_reviewed"),
  thirtyDayCounter: integer("thirty_day_counter").default(0),
  sixtyDayCounter: integer("sixty_day_counter").default(0),
  ninetyDayCounter: integer("ninety_day_counter").default(0),
  accountStatusCode: text("account_status_code"),
  accountStatusDescription: text("account_status_description"),
  rateCode: text("rate_code"),
  rateDescription: text("rate_description"),
  termsFrequencyCode: text("terms_frequency_code"),
  termsFrequencyDescription: text("terms_frequency_description"),
  termsDurationCode: text("terms_duration_code"),
  termsDurationDescription: text("terms_duration_description"),
  previousHighRate1: integer("previous_high_rate_1"),
  previousHighDate1: text("previous_high_date_1"),
  previousHighRate2: integer("previous_high_rate_2"),
  previousHighDate2: text("previous_high_date_2"),
  previousHighRate3: integer("previous_high_rate_3"),
  previousHighDate3: text("previous_high_date_3"),
  automatedUpdateIndicator: text("automated_update_indicator"),
  paymentHistory24: text("payment_history_24"),
  rawNarrativeCodes: jsonb("raw_narrative_codes"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const tradelineNarratives = pgTable("tradeline_narratives", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tradelineId: varchar("tradeline_id").notNull().references(() => tradelines.id, { onDelete: "cascade" }),
  narrativeCode: text("narrative_code").notNull(),
  narrativeDescription: text("narrative_description"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const tradelinePaymentHistory = pgTable("tradeline_payment_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tradelineId: varchar("tradeline_id").notNull().references(() => tradelines.id, { onDelete: "cascade" }),
  monthIndex: integer("month_index").notNull(),
  statusCode: text("status_code"),
  statusDescription: text("status_description"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const creditInquiries = pgTable("credit_inquiries", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  inquiryType: text("inquiry_type"),
  inquiryDate: text("inquiry_date").notNull(),
  customerNumber: text("customer_number"),
  customerName: text("customer_name"),
  industryCode: text("industry_code"),
  industryDescription: text("industry_description"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const fraudAlerts = pgTable("fraud_alerts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  alertTypeCode: text("alert_type_code"),
  alertTypeDescription: text("alert_type_description"),
  dateReported: text("date_reported"),
  effectiveDate: text("effective_date"),
  contactPhones: jsonb("contact_phones"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const ofacAlerts = pgTable("ofac_alerts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  memberFirmCode: text("member_firm_code"),
  cdcResponseCode: text("cdc_response_code"),
  transactionType: text("transaction_type"),
  cdcTransactionDate: text("cdc_transaction_date"),
  cdcTransactionTime: text("cdc_transaction_time"),
  legalVerbiage: text("legal_verbiage"),
  dataSegmentRegulated: text("data_segment_regulated"),
  revisedLegalVerbiageIndicator: integer("revised_legal_verbiage_indicator"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const dataxTransactions = pgTable("datax_transactions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  trackId: text("track_id"),
  trackHash: text("track_hash"),
  transactionId: text("transaction_id"),
  codeVersion: text("code_version"),
  requestVersion: integer("request_version"),
  generationTime: text("generation_time"),
  globalDecisionResult: text("global_decision_result"),
  craBucket: text("cra_bucket"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const dataxIndicators = pgTable("datax_indicators", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  indicatorCode: text("indicator_code").notNull(),
  indicatorCount: integer("indicator_count"),
  indicatorMessage: text("indicator_message"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const dataxSummary = pgTable("datax_summary", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  consumerId: varchar("consumer_id").notNull().references(() => consumers.id, { onDelete: "cascade" }),
  totalTradelines: integer("total_tradelines"),
  currentTradelines: integer("current_tradelines"),
  totalChargeOffs: integer("total_charge_offs"),
  totalRecoveries: integer("total_recoveries"),
  totalPaidOffs: integer("total_paid_offs"),
  firstPaymentDefaults: integer("first_payment_defaults"),
  firstPaymentFatals: integer("first_payment_fatals"),
  daysSinceLastAch: integer("days_since_last_ach"),
  daysSinceLastReturn: integer("days_since_last_return"),
  daysSinceLastTradeline: integer("days_since_last_tradeline"),
  daysSinceLastFatalReturn: integer("days_since_last_fatal_return"),
  lastPaymentDate: text("last_payment_date"),
  lastPaymentAmount: integer("last_payment_amount"),
  lastPaymentType: text("last_payment_type"),
  lastPaymentDisposition: text("last_payment_disposition"),
  lastReturnDate: text("last_return_date"),
  lastReturnReason: text("last_return_reason"),
  lastReturnMessage: text("last_return_message"),
  lastInquiryDate: text("last_inquiry_date"),
  lastTradelineDate: text("last_tradeline_date"),
  lastChargeOffDate: text("last_charge_off_date"),
  lastThreePayments: text("last_three_payments"),
  maximumOpenTradelines: integer("maximum_open_tradelines"),
  maximumTotalPrincipal: integer("maximum_total_principal"),
  maximumTradelinePrincipal: integer("maximum_tradeline_principal"),
  totalCurrentPrincipal: integer("total_current_principal"),
  totalAchDebitAttempts: integer("total_ach_debit_attempts"),
  totalUniqueMemberTradelines: integer("total_unique_member_tradelines"),
  tradelinesByInquiringMember: integer("tradelines_by_inquiring_member"),
  addressDiscrepancyIndicator: text("address_discrepancy_indicator"),
  rawSummaryData: jsonb("raw_summary_data"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertConsumerSchema = createInsertSchema(consumers).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertConsumerAddressSchema = createInsertSchema(consumerAddresses).omit({
  id: true,
  createdAt: true,
});

export const insertCreditScoreSchema = createInsertSchema(creditScores).omit({
  id: true,
  createdAt: true,
});

export const insertScoreFactorSchema = createInsertSchema(scoreFactors).omit({
  id: true,
  createdAt: true,
});

export const insertTradelineSchema = createInsertSchema(tradelines).omit({
  id: true,
  createdAt: true,
});

export const insertTradelineNarrativeSchema = createInsertSchema(tradelineNarratives).omit({
  id: true,
  createdAt: true,
});

export const insertTradelinePaymentHistorySchema = createInsertSchema(tradelinePaymentHistory).omit({
  id: true,
  createdAt: true,
});

export const insertCreditInquirySchema = createInsertSchema(creditInquiries).omit({
  id: true,
  createdAt: true,
});

export const insertFraudAlertSchema = createInsertSchema(fraudAlerts).omit({
  id: true,
  createdAt: true,
});

export const insertOfacAlertSchema = createInsertSchema(ofacAlerts).omit({
  id: true,
  createdAt: true,
});

export const insertDataxTransactionSchema = createInsertSchema(dataxTransactions).omit({
  id: true,
  createdAt: true,
});

export const insertDataxIndicatorSchema = createInsertSchema(dataxIndicators).omit({
  id: true,
  createdAt: true,
});

export const insertDataxSummarySchema = createInsertSchema(dataxSummary).omit({
  id: true,
  createdAt: true,
});

export type InsertConsumer = z.infer<typeof insertConsumerSchema>;
export type Consumer = typeof consumers.$inferSelect;

export type InsertConsumerAddress = z.infer<typeof insertConsumerAddressSchema>;
export type ConsumerAddress = typeof consumerAddresses.$inferSelect;

export type InsertCreditScore = z.infer<typeof insertCreditScoreSchema>;
export type CreditScore = typeof creditScores.$inferSelect;

export type InsertScoreFactor = z.infer<typeof insertScoreFactorSchema>;
export type ScoreFactor = typeof scoreFactors.$inferSelect;

export type InsertTradeline = z.infer<typeof insertTradelineSchema>;
export type Tradeline = typeof tradelines.$inferSelect;

export type InsertTradelineNarrative = z.infer<typeof insertTradelineNarrativeSchema>;
export type TradelineNarrative = typeof tradelineNarratives.$inferSelect;

export type InsertTradelinePaymentHistory = z.infer<typeof insertTradelinePaymentHistorySchema>;
export type TradelinePaymentHistory = typeof tradelinePaymentHistory.$inferSelect;

export type InsertCreditInquiry = z.infer<typeof insertCreditInquirySchema>;
export type CreditInquiry = typeof creditInquiries.$inferSelect;

export type InsertFraudAlert = z.infer<typeof insertFraudAlertSchema>;
export type FraudAlert = typeof fraudAlerts.$inferSelect;

export type InsertOfacAlert = z.infer<typeof insertOfacAlertSchema>;
export type OfacAlert = typeof ofacAlerts.$inferSelect;

export type InsertDataxTransaction = z.infer<typeof insertDataxTransactionSchema>;
export type DataxTransaction = typeof dataxTransactions.$inferSelect;

export type InsertDataxIndicator = z.infer<typeof insertDataxIndicatorSchema>;
export type DataxIndicator = typeof dataxIndicators.$inferSelect;

export type InsertDataxSummary = z.infer<typeof insertDataxSummarySchema>;
export type DataxSummary = typeof dataxSummary.$inferSelect;

export const ipWhitelist = pgTable("ip_whitelist", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  ipAddress: text("ip_address").notNull().unique(),
  description: text("description"),
  isEnabled: boolean("is_enabled").notNull().default(true),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertIpWhitelistSchema = createInsertSchema(ipWhitelist).omit({
  id: true,
  createdAt: true,
});

export type InsertIpWhitelist = z.infer<typeof insertIpWhitelistSchema>;
export type IpWhitelist = typeof ipWhitelist.$inferSelect;

export const apiClients = pgTable("api_clients", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  clientId: text("client_id").notNull().unique(),
  clientSecret: text("client_secret"),
  clientSecretHash: text("client_secret_hash").notNull(),
  isEnabled: boolean("is_enabled").notNull().default(true),
  lastUsedAt: timestamp("last_used_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const apiTokens = pgTable("api_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  clientId: varchar("client_id").notNull().references(() => apiClients.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  lastUsedAt: timestamp("last_used_at"),
  revokedAt: timestamp("revoked_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const apiRequestLogs = pgTable("api_request_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  clientId: varchar("client_id").references(() => apiClients.id, { onDelete: "set null" }),
  endpoint: text("endpoint").notNull(),
  method: text("method").notNull(),
  statusCode: integer("status_code"),
  durationMs: integer("duration_ms"),
  requestBody: jsonb("request_body"),
  responseBody: jsonb("response_body"),
  errorMessage: text("error_message"),
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertApiClientSchema = createInsertSchema(apiClients).omit({
  id: true,
  createdAt: true,
  lastUsedAt: true,
});

export const insertApiTokenSchema = createInsertSchema(apiTokens).omit({
  id: true,
  createdAt: true,
  lastUsedAt: true,
  revokedAt: true,
});

export const insertApiRequestLogSchema = createInsertSchema(apiRequestLogs).omit({
  id: true,
  createdAt: true,
});

// Geocoded addresses table - stores address lookups from Census and Google Maps
export const geocodedAddresses = pgTable("geocoded_addresses", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  inputAddress: text("input_address").notNull(),
  
  // Census Bureau geocoder results
  censusMatched: boolean("census_matched").default(false),
  censusMatchedAddress: text("census_matched_address"),
  censusLatitude: decimal("census_latitude", { precision: 10, scale: 7 }),
  censusLongitude: decimal("census_longitude", { precision: 10, scale: 7 }),
  censusCounty: text("census_county"),
  censusState: text("census_state"),
  censusTract: text("census_tract"),
  censusTractGeoid: text("census_tract_geoid"),
  censusBlockGroup: text("census_block_group"),
  censusStateFips: text("census_state_fips"),
  censusCountyFips: text("census_county_fips"),
  censusTractCode: text("census_tract_code"),
  
  // Google Maps geocoder results
  googleMatched: boolean("google_matched").default(false),
  googleFormattedAddress: text("google_formatted_address"),
  googleLatitude: decimal("google_latitude", { precision: 10, scale: 7 }),
  googleLongitude: decimal("google_longitude", { precision: 10, scale: 7 }),
  googleCounty: text("google_county"),
  googleState: text("google_state"),
  googleCity: text("google_city"),
  googleZipCode: text("google_zip_code"),
  googlePlaceId: text("google_place_id"),
  
  // USPS Address Validation results
  uspsMatched: boolean("usps_matched").default(false),
  uspsAddress1: text("usps_address1"),
  uspsAddress2: text("usps_address2"),
  uspsCity: text("usps_city"),
  uspsState: text("usps_state"),
  uspsZip5: text("usps_zip5"),
  uspsZip4: text("usps_zip4"),
  uspsDeliveryPoint: text("usps_delivery_point"),
  uspsCarrierRoute: text("usps_carrier_route"),
  uspsDpvConfirmation: text("usps_dpv_confirmation"),
  uspsDpvFootnotes: text("usps_dpv_footnotes"),
  uspsResidentialIndicator: text("usps_residential_indicator"),
  uspsRecordType: text("usps_record_type"),
  uspsError: text("usps_error"),
  
  // Income data from Census ACS
  medianHouseholdIncome: integer("median_household_income"),
  medianFamilyIncome: integer("median_family_income"),
  perCapitaIncome: integer("per_capita_income"),
  incomeSource: text("income_source"),
  
  // LMI designation
  lmiDesignation: text("lmi_designation"),
  lmiTractMedianIncome: integer("lmi_tract_median_income"),
  lmiStateMedianIncome: integer("lmi_state_median_income"),
  lmiIncomeRatioPercent: integer("lmi_income_ratio_percent"),
  isLmiTract: boolean("is_lmi_tract").default(false),
  
  // Source tracking (api, browser)
  source: text("source").default("browser"),
  
  // Normalized address JSON (stores the complete normalized output)
  normalizedAddress: jsonb("normalized_address"),
  
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertGeocodedAddressSchema = createInsertSchema(geocodedAddresses).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertApiClient = z.infer<typeof insertApiClientSchema>;
export type ApiClient = typeof apiClients.$inferSelect;

export type InsertApiToken = z.infer<typeof insertApiTokenSchema>;
export type ApiToken = typeof apiTokens.$inferSelect;

export type InsertApiRequestLog = z.infer<typeof insertApiRequestLogSchema>;
export type ApiRequestLog = typeof apiRequestLogs.$inferSelect;

export type InsertGeocodedAddress = z.infer<typeof insertGeocodedAddressSchema>;
export type GeocodedAddress = typeof geocodedAddresses.$inferSelect;

// USPS Credentials table - stores USPS API credential sets with usage tracking
export const uspsCredentials = pgTable("usps_credentials", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name"),
  clientId: text("client_id").notNull(),
  clientSecret: text("client_secret").notNull(),
  userId: text("user_id"),
  isActive: boolean("is_active").notNull().default(true),
  dailyQuota: integer("daily_quota").default(1000),
  lastUsedAt: timestamp("last_used_at"),
  usageCountSinceReset: integer("usage_count_since_reset").notNull().default(0),
  resetAt: timestamp("reset_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertUspsCredentialSchema = createInsertSchema(uspsCredentials).omit({
  id: true,
  createdAt: true,
  lastUsedAt: true,
  usageCountSinceReset: true,
  resetAt: true,
});

export type InsertUspsCredential = z.infer<typeof insertUspsCredentialSchema>;
export type UspsCredential = typeof uspsCredentials.$inferSelect;

// App Settings table - stores global application settings
export const appSettings = pgTable("app_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  key: text("key").notNull().unique(),
  value: text("value").notNull(),
  description: text("description"),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertAppSettingSchema = createInsertSchema(appSettings).omit({
  id: true,
  updatedAt: true,
});

export type InsertAppSetting = z.infer<typeof insertAppSettingSchema>;
export type AppSetting = typeof appSettings.$inferSelect;
