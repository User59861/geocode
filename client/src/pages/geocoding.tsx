import { useState, useEffect, useRef, useMemo } from "react";
import { ArrowLeft, Copy, Check, Eye, EyeOff, Loader2, MapPin, Navigation, DollarSign, TrendingUp, History, Trash2, ChevronDown, ChevronUp, Building2, Search, RefreshCw, Github } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface PlacePrediction {
  placeId: string;
  description: string;
  mainText: string;
  secondaryText: string;
}

interface NearbyBusiness {
  placeId: string;
  name: string;
  address: string;
  type: string;
  types: string[];
}

interface NormalizedAddressJson {
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
  coordinates: { latitude: number | null; longitude: number | null } | null;
  corrections: Array<{ code: string; text: string }>;
  sources: Record<string, string | null>;
}

interface SavedAddress {
  id: string;
  inputAddress: string;
  censusMatched: boolean;
  censusMatchedAddress: string | null;
  censusCounty: string | null;
  censusState: string | null;
  censusTract: string | null;
  censusTractGeoid: string | null;
  censusLatitude: string | null;
  censusLongitude: string | null;
  googleMatched: boolean;
  googleFormattedAddress: string | null;
  googleCity: string | null;
  googleCounty: string | null;
  googleState: string | null;
  googleZipCode: string | null;
  googleLatitude: string | null;
  googleLongitude: string | null;
  uspsMatched: boolean;
  uspsCity: string | null;
  uspsState: string | null;
  uspsZip5: string | null;
  uspsZip4: string | null;
  uspsAddress2: string | null;
  medianHouseholdIncome: number | null;
  lmiDesignation: string | null;
  isLmiTract: boolean;
  source: string | null;
  normalizedAddress: NormalizedAddressJson | null;
  createdAt: string;
}

interface GeocodingResult {
  census: {
    matched?: boolean;
    matchedAddress?: string;
    coordinates?: { latitude: number; longitude: number };
    county?: string;
    state?: string;
    tract?: string;
    tractGeoid?: string;
    blockGroup?: string;
    stateFips?: string;
    countyFips?: string;
    tractCode?: string;
    income?: {
      medianHouseholdIncome: number | null;
      medianFamilyIncome: number | null;
      perCapitaIncome: number | null;
      source: string;
    };
    lmi?: {
      designation: string;
      tractMedianIncome: number;
      stateMedianIncome: number;
      incomeRatioPercent: number;
      isLmiTract: boolean;
      description: string;
    };
    incomeError?: string;
    error?: boolean;
    message?: string;
    raw?: any;
  } | null;
  google: {
    matched?: boolean;
    formattedAddress?: string;
    coordinates?: { latitude: number; longitude: number };
    county?: string;
    state?: string;
    city?: string;
    zipCode?: string;
    placeId?: string;
    configured?: boolean;
    error?: boolean;
    message?: string;
    raw?: any;
  } | null;
  usps: {
    matched?: boolean;
    address1?: string;
    address2?: string;
    city?: string;
    state?: string;
    zip5?: string;
    zip4?: string;
    fullZip?: string;
    deliveryPoint?: string;
    carrierRoute?: string;
    dpvConfirmation?: string;
    dpvFootnotes?: string;
    residential?: string;
    recordType?: string;
    corrections?: Array<{ code: string; text: string }>;
    configured?: boolean;
    error?: boolean;
    message?: string;
    raw?: any;
  } | null;
  normalizedAddress?: NormalizedAddressJson | null;
  savedId?: string;
}

export default function Geocoding() {
  const [geoAddress, setGeoAddress] = useState("");
  const [geoLoading, setGeoLoading] = useState(false);
  const [geoResult, setGeoResult] = useState<GeocodingResult | null>(null);
  const [showRawGeo, setShowRawGeo] = useState<"census" | "google" | "usps" | null>(null);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [savedAddresses, setSavedAddresses] = useState<SavedAddress[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  
  const [businessQuery, setBusinessQuery] = useState("");
  const [predictions, setPredictions] = useState<PlacePrediction[]>([]);
  const [searchingBusiness, setSearchingBusiness] = useState(false);
  const [showPredictions, setShowPredictions] = useState(false);
  const [nearbyBusinesses, setNearbyBusinesses] = useState<NearbyBusiness[]>([]);
  const [loadingNearby, setLoadingNearby] = useState(false);
  const [expandedHistoryJson, setExpandedHistoryJson] = useState<Set<string>>(new Set());
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const [syncStatus, setSyncStatus] = useState<{ configured: boolean; repo: string } | null>(null);
  const [syncing, setSyncing] = useState<"push" | "pull" | null>(null);
  const [syncResult, setSyncResult] = useState<{ success: boolean; message: string } | null>(null);
  const [showSyncMenu, setShowSyncMenu] = useState(false);
  const syncMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/github/status")
      .then(res => res.json())
      .then(data => setSyncStatus(data))
      .catch(() => setSyncStatus(null));
  }, []);

  useEffect(() => {
    const handleClickOutsideSync = (event: MouseEvent) => {
      if (syncMenuRef.current && !syncMenuRef.current.contains(event.target as Node)) {
        setShowSyncMenu(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutsideSync);
    return () => document.removeEventListener("mousedown", handleClickOutsideSync);
  }, []);

  const handleSync = async (action: "push" | "pull") => {
    setSyncing(action);
    setSyncResult(null);
    setShowSyncMenu(false);
    try {
      const response = await fetch(`/api/github/${action}`, { method: "POST" });
      const result = await response.json();
      setSyncResult(result);
      setTimeout(() => setSyncResult(null), 5000);
    } catch (error: any) {
      setSyncResult({ success: false, message: error.message });
    } finally {
      setSyncing(null);
    }
  };

  const getNormalizedAddressFromHistory = (addr: SavedAddress): NormalizedAddressJson | null => {
    // Use the stored normalized address if available
    // Older records without stored normalized address will return null
    return addr.normalizedAddress || null;
  };

  const toggleHistoryJson = (id: string) => {
    setExpandedHistoryJson(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowPredictions(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const searchBusiness = async (query: string) => {
    if (query.length < 2) {
      setPredictions([]);
      return;
    }
    
    setSearchingBusiness(true);
    try {
      const response = await fetch(`/api/places/autocomplete?input=${encodeURIComponent(query)}`);
      const data = await response.json();
      if (data.predictions) {
        setPredictions(data.predictions);
        setShowPredictions(true);
      }
    } catch (error) {
      console.error("Business search failed:", error);
    } finally {
      setSearchingBusiness(false);
    }
  };

  const handleBusinessQueryChange = (value: string) => {
    setBusinessQuery(value);
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    searchTimeoutRef.current = setTimeout(() => {
      searchBusiness(value);
    }, 300);
  };

  const selectBusiness = async (prediction: PlacePrediction) => {
    setShowPredictions(false);
    setBusinessQuery(prediction.mainText);
    
    try {
      const response = await fetch(`/api/places/details/${prediction.placeId}`);
      const data = await response.json();
      const address = data.formattedAddress || data.address;
      if (address) {
        setGeoAddress(address);
      } else {
        console.error("No address returned for place:", prediction.placeId);
      }
    } catch (error) {
      console.error("Failed to get place details:", error);
    }
  };

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const response = await fetch("/api/geocoded-addresses?limit=50");
      const data = await response.json();
      setSavedAddresses(data);
    } catch (error) {
      console.error("Failed to fetch history:", error);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const deleteAddress = async (id: string) => {
    try {
      await fetch(`/api/geocoded-addresses/${id}`, { method: "DELETE" });
      setSavedAddresses(prev => prev.filter(a => a.id !== id));
    } catch (error) {
      console.error("Failed to delete address:", error);
    }
  };

  const copyToClipboard = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const formatCurrency = (value: number | null | undefined) => {
    if (value === null || value === undefined) return "N/A";
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(value);
  };

  const handleGeocode = async () => {
    if (!geoAddress.trim()) {
      alert("Please enter an address");
      return;
    }

    setGeoLoading(true);
    setGeoResult(null);
    setShowRawGeo(null);
    setNearbyBusinesses([]);

    try {
      const response = await fetch("/api/geocode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: geoAddress }),
      });
      const data = await response.json();
      setGeoResult(data);
      // Refresh history after successful lookup
      fetchHistory();
      
      // Fetch nearby businesses if we have coordinates
      const lat = data.google?.coordinates?.latitude || data.census?.coordinates?.latitude;
      const lng = data.google?.coordinates?.longitude || data.census?.coordinates?.longitude;
      if (lat && lng) {
        fetchNearbyBusinesses(lat, lng, geoAddress);
      }
    } catch (error: any) {
      console.error("Geocoding failed:", error);
      setGeoResult({
        census: { error: true, message: error.message },
        google: { error: true, message: error.message },
        usps: { error: true, message: error.message },
      });
    } finally {
      setGeoLoading(false);
    }
  };

  const fetchNearbyBusinesses = async (lat: number, lng: number, address: string) => {
    setLoadingNearby(true);
    try {
      const response = await fetch(`/api/places/nearby?lat=${lat}&lng=${lng}&address=${encodeURIComponent(address)}`);
      const data = await response.json();
      if (data.businesses) {
        setNearbyBusinesses(data.businesses);
      }
    } catch (error) {
      console.error("Failed to fetch nearby businesses:", error);
    } finally {
      setLoadingNearby(false);
    }
  };

  const getLmiColor = (designation: string) => {
    switch (designation) {
      case "Low": return "bg-red-100 text-red-800 border-red-200";
      case "Moderate": return "bg-amber-100 text-amber-800 border-amber-200";
      case "Middle": return "bg-blue-100 text-blue-800 border-blue-200";
      case "Upper": return "bg-emerald-100 text-emerald-800 border-emerald-200";
      default: return "bg-slate-100 text-slate-800 border-slate-200";
    }
  };

  const JsonViewer = ({ data, section }: { data: any; section: string }) => {
    const jsonString = JSON.stringify(data, null, 2);
    return (
      <div className="relative">
        <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm max-h-96 overflow-y-auto">
          <code>{jsonString}</code>
        </pre>
        <button
          onClick={() => copyToClipboard(jsonString, section)}
          className="absolute top-2 right-2 p-2 bg-slate-700 hover:bg-slate-600 rounded text-slate-300"
          title="Copy"
          data-testid={`button-copy-${section}`}
        >
          {copiedSection === section ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <Link href="/">
              <Button variant="ghost" size="sm" className="gap-2" data-testid="link-back-dashboard">
                <ArrowLeft className="w-4 h-4" />
                Dashboard
              </Button>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-slate-900">Address Geocoding Tool</h1>
              <p className="text-slate-500">Look up address coordinates, census tract, and income data</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {syncResult && (
              <div className={`text-sm px-3 py-1 rounded ${syncResult.success ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'}`}>
                {syncResult.message}
              </div>
            )}
            <div className="relative" ref={syncMenuRef}>
              <button
                onClick={() => setShowSyncMenu(!showSyncMenu)}
                disabled={syncing !== null || !syncStatus?.configured}
                className="flex items-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white rounded-lg text-sm font-medium transition-colors"
                data-testid="button-github-sync"
              >
                {syncing ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Github className="w-4 h-4" />
                )}
                {syncing === "push" ? "Pushing..." : syncing === "pull" ? "Pulling..." : "Address Lookup Sync"}
                <ChevronDown className="w-3 h-3" />
              </button>
              {showSyncMenu && (
                <div className="absolute right-0 mt-2 w-48 bg-white border border-slate-200 rounded-lg shadow-lg z-50">
                  <button
                    onClick={() => handleSync("push")}
                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 flex items-center gap-2"
                    data-testid="button-github-push"
                  >
                    <ArrowLeft className="w-4 h-4 rotate-180" />
                    Push Code to GitHub
                  </button>
                  <button
                    onClick={() => handleSync("pull")}
                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 flex items-center gap-2"
                    data-testid="button-github-pull"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    Pull Code from GitHub
                  </button>
                  <hr className="my-1" />
                  <a
                    href="https://github.com/User59861/geocode"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block w-full px-4 py-2 text-left text-sm hover:bg-slate-50"
                    data-testid="link-github-view"
                  >
                    View Repository
                  </a>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <MapPin className="w-5 h-5 text-emerald-600" />
            <h2 className="text-xl font-bold text-slate-800">Address Lookup</h2>
          </div>
          <p className="text-slate-600 text-sm mb-4">
            Enter a US address to get coordinates, census tract, income data, and LMI designation.
          </p>

          <div className="space-y-4">
            <div className="relative" ref={dropdownRef}>
              <Label htmlFor="businessSearch" className="flex items-center gap-2">
                <Building2 className="w-4 h-4 text-slate-500" />
                Search by Business Name
              </Label>
              <div className="relative mt-1">
                <Input
                  id="businessSearch"
                  value={businessQuery}
                  onChange={(e) => handleBusinessQueryChange(e.target.value)}
                  onFocus={() => predictions.length > 0 && setShowPredictions(true)}
                  placeholder="e.g. Starbucks, Bank of America, McDonald's..."
                  className="pr-10"
                  data-testid="input-business-search"
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  {searchingBusiness ? (
                    <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
                  ) : (
                    <Search className="w-4 h-4 text-slate-400" />
                  )}
                </div>
              </div>
              {showPredictions && predictions.length > 0 && (
                <div className="absolute z-10 w-full mt-1 bg-white border border-slate-200 rounded-lg shadow-lg max-h-64 overflow-y-auto">
                  {predictions.map((prediction) => (
                    <button
                      key={prediction.placeId}
                      onClick={() => selectBusiness(prediction)}
                      className="w-full px-4 py-3 text-left hover:bg-slate-50 border-b border-slate-100 last:border-b-0"
                      data-testid={`prediction-${prediction.placeId}`}
                    >
                      <div className="font-medium text-slate-800">{prediction.mainText}</div>
                      <div className="text-sm text-slate-500">{prediction.secondaryText}</div>
                    </button>
                  ))}
                </div>
              )}
              <p className="text-xs text-slate-500 mt-1">
                Type a business name to find its address automatically
              </p>
            </div>

            <div className="relative flex items-center gap-4 py-2">
              <div className="flex-1 border-t border-slate-200"></div>
              <span className="text-xs text-slate-400 uppercase">or enter address directly</span>
              <div className="flex-1 border-t border-slate-200"></div>
            </div>

            <div>
              <Label htmlFor="geoAddress">Full Address</Label>
              <Input
                id="geoAddress"
                value={geoAddress}
                onChange={(e) => setGeoAddress(e.target.value)}
                placeholder="123 Main St, Dallas, TX 75201"
                className="font-mono"
                data-testid="input-geocode-address"
                onKeyDown={(e) => e.key === "Enter" && handleGeocode()}
              />
            </div>

            <Button
              onClick={handleGeocode}
              disabled={geoLoading || !geoAddress.trim()}
              className="w-full gap-2"
              data-testid="button-geocode"
            >
              {geoLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Navigation className="w-4 h-4" />
              )}
              Look Up Address
            </Button>

            {/* Parsed Address Fields */}
            {geoResult && (geoResult.google?.matched || geoResult.census?.matched) && geoResult.normalizedAddress && (() => {
              const normalized = geoResult.normalizedAddress;
              return (
                <div className="mt-4 p-4 bg-slate-50 rounded-lg border border-slate-200">
                  <h3 className="text-sm font-semibold text-slate-700 mb-3">Parsed Address</h3>
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                    <div>
                      <Label className="text-xs text-slate-500">Street Number</Label>
                      <Input
                        readOnly
                        value={normalized.streetNumber}
                        className={`text-sm ${normalized.streetNumber ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-street-number"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">Direction</Label>
                      <Input
                        readOnly
                        value={normalized.streetDirection}
                        className={`text-sm ${normalized.streetDirection ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-direction"
                      />
                    </div>
                    <div className="col-span-2 md:col-span-1">
                      <Label className="text-xs text-slate-500">Street Name</Label>
                      <Input
                        readOnly
                        value={normalized.streetName}
                        className={`text-sm ${normalized.streetName ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-street-name"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">Street Type</Label>
                      <Input
                        readOnly
                        value={normalized.streetType}
                        className={`text-sm ${normalized.streetType ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-street-type"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">Unit/Suite/Apt</Label>
                      <Input
                        readOnly
                        value={normalized.unitNumber}
                        className={`text-sm ${normalized.unitNumber ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-unit"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">City</Label>
                      <Input
                        readOnly
                        value={normalized.city}
                        className={`text-sm ${normalized.city ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-city"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">County</Label>
                      <Input
                        readOnly
                        value={normalized.county}
                        className={`text-sm ${normalized.county ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-county"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">State</Label>
                      <Input
                        readOnly
                        value={normalized.state}
                        className={`text-sm ${normalized.state ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-state"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">ZIP Code</Label>
                      <Input
                        readOnly
                        value={normalized.zipCode}
                        className={`text-sm ${normalized.zipCode ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-zip"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">ZIP+4</Label>
                      <Input
                        readOnly
                        value={normalized.zip4}
                        className={`text-sm ${normalized.zip4 ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-zip4"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-slate-500">Country</Label>
                      <Input
                        readOnly
                        value={normalized.country}
                        className={`text-sm ${normalized.country ? 'bg-white' : 'bg-slate-100 text-slate-400'}`}
                        data-testid="input-parsed-country"
                      />
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>
        </div>

        {geoResult && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-6">
              <div className="p-5 bg-blue-50 border border-blue-200 rounded-xl">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold text-blue-800 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-blue-600"></span>
                    Census Bureau Geocoder
                  </h3>
                  <button
                    onClick={() => setShowRawGeo(showRawGeo === "census" ? null : "census")}
                    className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1"
                    data-testid="button-toggle-raw-census"
                  >
                    {showRawGeo === "census" ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    {showRawGeo === "census" ? "Hide" : "Show"} Raw
                  </button>
                </div>
                {geoResult.census?.error ? (
                  <p className="text-red-600 text-sm">{geoResult.census.message}</p>
                ) : geoResult.census?.matched ? (
                  <div className="space-y-2 text-sm">
                    <p><span className="font-medium text-slate-700">Matched:</span> {geoResult.census.matchedAddress}</p>
                    <p><span className="font-medium text-slate-700">Coordinates:</span> {geoResult.census.coordinates?.latitude?.toFixed(6)}, {geoResult.census.coordinates?.longitude?.toFixed(6)}</p>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">County:</span> {geoResult.census.county}</p>
                      <p><span className="font-medium text-slate-700">State:</span> {geoResult.census.state}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">Census Tract:</span> {geoResult.census.tract}</p>
                      <p><span className="font-medium text-slate-700">Block Group:</span> {geoResult.census.blockGroup}</p>
                    </div>
                    {geoResult.census.tractGeoid && (
                      <p><span className="font-medium text-slate-700">Tract GEOID:</span> <code className="text-xs bg-blue-100 px-1 rounded">{geoResult.census.tractGeoid}</code></p>
                    )}
                  </div>
                ) : (
                  <p className="text-amber-600 text-sm">No match found</p>
                )}
                {showRawGeo === "census" && geoResult.census?.raw && (
                  <div className="mt-3">
                    <JsonViewer data={geoResult.census.raw} section="census-raw" />
                  </div>
                )}
              </div>

              <div className="p-5 bg-green-50 border border-green-200 rounded-xl">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold text-green-800 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-green-600"></span>
                    Google Maps Geocoder
                  </h3>
                  <button
                    onClick={() => setShowRawGeo(showRawGeo === "google" ? null : "google")}
                    className="text-xs text-green-600 hover:text-green-800 flex items-center gap-1"
                    data-testid="button-toggle-raw-google"
                  >
                    {showRawGeo === "google" ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    {showRawGeo === "google" ? "Hide" : "Show"} Raw
                  </button>
                </div>
                {!geoResult.google?.configured ? (
                  <p className="text-slate-500 text-sm">Google Maps API not configured (GOOGLE_MAPS_API_KEY not set)</p>
                ) : geoResult.google?.error ? (
                  <p className="text-red-600 text-sm">{geoResult.google.message}</p>
                ) : geoResult.google?.matched ? (
                  <div className="space-y-2 text-sm">
                    <p><span className="font-medium text-slate-700">Formatted:</span> {geoResult.google.formattedAddress}</p>
                    <p><span className="font-medium text-slate-700">Coordinates:</span> {geoResult.google.coordinates?.latitude?.toFixed(6)}, {geoResult.google.coordinates?.longitude?.toFixed(6)}</p>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">City:</span> {geoResult.google.city || "N/A"}</p>
                      <p><span className="font-medium text-slate-700">County:</span> {geoResult.google.county}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">State:</span> {geoResult.google.state}</p>
                      <p><span className="font-medium text-slate-700">ZIP Code:</span> {geoResult.google.zipCode}</p>
                    </div>
                    <p className="break-all"><span className="font-medium text-slate-700">Place ID:</span> <code className="text-xs bg-green-100 px-1 rounded break-all">{geoResult.google.placeId}</code></p>
                  </div>
                ) : (
                  <p className="text-amber-600 text-sm">No match found</p>
                )}
                {showRawGeo === "google" && geoResult.google?.raw && (
                  <div className="mt-3">
                    <JsonViewer data={geoResult.google.raw} section="google-raw" />
                  </div>
                )}
              </div>

              <div className="p-5 bg-orange-50 border border-orange-200 rounded-xl">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold text-orange-800 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-orange-600"></span>
                    USPS Address Validation
                  </h3>
                  <button
                    onClick={() => setShowRawGeo(showRawGeo === "usps" ? null : "usps")}
                    className="text-xs text-orange-600 hover:text-orange-800 flex items-center gap-1"
                    data-testid="button-toggle-raw-usps"
                  >
                    {showRawGeo === "usps" ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    {showRawGeo === "usps" ? "Hide" : "Show"} Raw
                  </button>
                </div>
                {!geoResult.usps?.configured ? (
                  <p className="text-slate-500 text-sm">USPS API not configured (USPS_USER_ID not set)</p>
                ) : geoResult.usps?.error ? (
                  <p className="text-red-600 text-sm">{geoResult.usps.message}</p>
                ) : geoResult.usps?.matched ? (
                  <div className="space-y-2 text-sm">
                    {geoResult.usps.address1 && (
                      <p><span className="font-medium text-slate-700">Address Line 1:</span> {geoResult.usps.address1}</p>
                    )}
                    <p><span className="font-medium text-slate-700">Address Line 2:</span> {geoResult.usps.address2}</p>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">City:</span> {geoResult.usps.city}</p>
                      <p><span className="font-medium text-slate-700">State:</span> {geoResult.usps.state}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">ZIP+4:</span> {geoResult.usps.fullZip}</p>
                      <p><span className="font-medium text-slate-700">Carrier Route:</span> {geoResult.usps.carrierRoute || "N/A"}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <p><span className="font-medium text-slate-700">Delivery Point:</span> {geoResult.usps.deliveryPoint || "N/A"}</p>
                      <p><span className="font-medium text-slate-700">Residential:</span> {geoResult.usps.residential === "Y" ? "Yes" : geoResult.usps.residential === "N" ? "No" : "Unknown"}</p>
                    </div>
                    {geoResult.usps.dpvConfirmation && (
                      <p><span className="font-medium text-slate-700">DPV Confirmation:</span> <code className="text-xs bg-orange-100 px-1 rounded">{geoResult.usps.dpvConfirmation}</code></p>
                    )}
                    {geoResult.usps.corrections && geoResult.usps.corrections.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-orange-200">
                        <p className="font-medium text-slate-700 mb-2">Corrections:</p>
                        <div className="space-y-2">
                          {geoResult.usps.corrections.map((correction: any, idx: number) => (
                            <div key={idx} className="bg-orange-100 rounded p-2" data-testid={`usps-correction-${idx}`}>
                              <span className="font-mono text-xs text-orange-800 font-semibold">Code {correction.code}:</span>
                              <p className="text-sm text-orange-900 mt-1">{correction.text}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-amber-600 text-sm">No match found</p>
                )}
                {showRawGeo === "usps" && geoResult.usps?.raw && (
                  <div className="mt-3">
                    <JsonViewer data={geoResult.usps.raw} section="usps-raw" />
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-6">
              {geoResult.census?.matched && (
                <>
                  <div className="p-5 bg-purple-50 border border-purple-200 rounded-xl">
                    <div className="flex items-center gap-2 mb-3">
                      <DollarSign className="w-5 h-5 text-purple-600" />
                      <h3 className="font-semibold text-purple-800">Income Data (Census ACS)</h3>
                    </div>
                    {geoResult.census.income ? (
                      <div className="space-y-3">
                        <div className="grid grid-cols-1 gap-3">
                          <div className="bg-white rounded-lg p-3 border border-purple-100">
                            <div className="text-xs text-purple-600 font-medium">Median Household Income</div>
                            <div className="text-2xl font-bold text-slate-900">{formatCurrency(geoResult.census.income.medianHouseholdIncome)}</div>
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            <div className="bg-white rounded-lg p-3 border border-purple-100">
                              <div className="text-xs text-purple-600 font-medium">Median Family Income</div>
                              <div className="text-lg font-semibold text-slate-900">{formatCurrency(geoResult.census.income.medianFamilyIncome)}</div>
                            </div>
                            <div className="bg-white rounded-lg p-3 border border-purple-100">
                              <div className="text-xs text-purple-600 font-medium">Per Capita Income</div>
                              <div className="text-lg font-semibold text-slate-900">{formatCurrency(geoResult.census.income.perCapitaIncome)}</div>
                            </div>
                          </div>
                        </div>
                        <p className="text-xs text-purple-600">{geoResult.census.income.source}</p>
                      </div>
                    ) : geoResult.census.incomeError ? (
                      <p className="text-red-600 text-sm">Error loading income data: {geoResult.census.incomeError}</p>
                    ) : (
                      <p className="text-slate-500 text-sm">Income data not available for this tract</p>
                    )}
                  </div>

                  {geoResult.census.lmi && (
                    <div className="p-5 bg-amber-50 border border-amber-200 rounded-xl">
                      <div className="flex items-center gap-2 mb-3">
                        <TrendingUp className="w-5 h-5 text-amber-600" />
                        <h3 className="font-semibold text-amber-800">LMI Designation</h3>
                      </div>
                      <div className="space-y-3">
                        <div className="flex items-center gap-3">
                          <span className={`px-4 py-2 rounded-lg font-bold text-lg border ${getLmiColor(geoResult.census.lmi.designation)}`}>
                            {geoResult.census.lmi.designation} Income
                          </span>
                          {geoResult.census.lmi.isLmiTract && (
                            <span className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm font-medium">
                              LMI Tract
                            </span>
                          )}
                        </div>
                        <div className="bg-white rounded-lg p-4 border border-amber-100">
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-sm text-slate-600">Tract vs State Median</span>
                            <span className="font-bold text-lg">{geoResult.census.lmi.incomeRatioPercent}%</span>
                          </div>
                          <div className="w-full bg-slate-200 rounded-full h-3">
                            <div 
                              className={`h-3 rounded-full ${
                                geoResult.census.lmi.incomeRatioPercent < 50 ? 'bg-red-500' :
                                geoResult.census.lmi.incomeRatioPercent < 80 ? 'bg-amber-500' :
                                geoResult.census.lmi.incomeRatioPercent < 120 ? 'bg-blue-500' : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(geoResult.census.lmi.incomeRatioPercent, 150)}%`, maxWidth: '100%' }}
                            />
                          </div>
                          <div className="flex justify-between text-xs text-slate-500 mt-1">
                            <span>Low (&lt;50%)</span>
                            <span>Moderate (&lt;80%)</span>
                            <span>Middle</span>
                            <span>Upper</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div>
                            <span className="text-slate-600">Tract Median:</span>
                            <span className="font-medium ml-1">{formatCurrency(geoResult.census.lmi.tractMedianIncome)}</span>
                          </div>
                          <div>
                            <span className="text-slate-600">State Median:</span>
                            <span className="font-medium ml-1">{formatCurrency(geoResult.census.lmi.stateMedianIncome)}</span>
                          </div>
                        </div>
                        <p className="text-xs text-amber-700 bg-amber-100 px-2 py-1 rounded">
                          {geoResult.census.lmi.description}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Normalized Address JSON */}
                  <div className="p-5 bg-slate-50 border border-slate-200 rounded-xl">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="w-5 h-5 text-slate-600 font-mono text-sm">{"{}"}</span>
                      <h3 className="font-semibold text-slate-800">Normalized Address (JSON)</h3>
                    </div>
                    <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-xs overflow-x-auto" data-testid="normalized-address-json">
                      {JSON.stringify(geoResult.normalizedAddress, null, 2)}
                    </pre>
                  </div>
                </>
              )}

              {!geoResult.census?.matched && (
                <div className="p-5 bg-slate-50 border border-slate-200 rounded-xl">
                  <div className="flex items-center gap-2 mb-3">
                    <DollarSign className="w-5 h-5 text-slate-400" />
                    <h3 className="font-semibold text-slate-600">Income & LMI Data</h3>
                  </div>
                  <p className="text-slate-500 text-sm">
                    Income and LMI data requires a Census Bureau address match. The Census geocoder did not find a match for this address.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Nearby Businesses at Address */}
        {geoResult && (geoResult.google?.matched || geoResult.census?.matched) && (
          <div className="mt-6 bg-white rounded-xl shadow-sm border border-slate-200 p-6">
            <div className="flex items-center gap-2 mb-4">
              <Building2 className="w-5 h-5 text-indigo-600" />
              <h2 className="text-xl font-bold text-slate-800">Businesses at This Address</h2>
            </div>
            {loadingNearby ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
                <span className="ml-2 text-slate-500">Finding businesses...</span>
              </div>
            ) : nearbyBusinesses.length === 0 ? (
              <p className="text-slate-500 text-sm">No businesses found at this exact location.</p>
            ) : (
              <div className="grid gap-3">
                {nearbyBusinesses.map((biz) => (
                  <div
                    key={biz.placeId}
                    className="p-4 bg-slate-50 rounded-lg border border-slate-200"
                    data-testid={`business-${biz.placeId}`}
                  >
                    <div className="font-medium text-slate-800">{biz.name}</div>
                    <div className="text-sm text-slate-600">{biz.address}</div>
                    {biz.type && (
                      <span className="inline-block mt-2 px-2 py-0.5 bg-indigo-100 text-indigo-700 text-xs rounded">
                        {biz.type.replace(/_/g, " ")}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Address Lookup History */}
        <div className="mt-8 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div className="px-6 py-4 flex items-center justify-between">
            <button
              onClick={() => setShowHistory(!showHistory)}
              className="flex items-center gap-2 hover:bg-slate-50 transition-colors rounded px-2 py-1 -ml-2"
              data-testid="button-toggle-history"
            >
              <History className="w-5 h-5 text-slate-600" />
              <span className="font-semibold text-slate-800">Lookup History</span>
              <span className="text-sm text-slate-500">({savedAddresses.length} saved)</span>
              {showHistory ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
            </button>
            <button
              onClick={() => fetchHistory()}
              disabled={loadingHistory}
              className="p-2 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded transition-colors disabled:opacity-50"
              title="Refresh data"
              data-testid="button-refresh-history"
            >
              <RefreshCw className={`w-4 h-4 ${loadingHistory ? 'animate-spin' : ''}`} />
            </button>
          </div>
          
          {showHistory && (
            <div className="border-t border-slate-200">
              {loadingHistory ? (
                <div className="p-6 flex items-center justify-center">
                  <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
                </div>
              ) : savedAddresses.length === 0 ? (
                <div className="p-6 text-center text-slate-500">
                  No addresses looked up yet. Use the form above to look up an address.
                </div>
              ) : (
                <div className="divide-y divide-slate-100 max-h-96 overflow-y-auto">
                  {savedAddresses.map((addr) => (
                    <div key={addr.id} className="px-6 py-4 hover:bg-slate-50" data-testid={`row-address-${addr.id}`}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <p className="font-medium text-slate-800 truncate">{addr.inputAddress}</p>
                          <div className="flex flex-wrap gap-2 mt-2">
                            {addr.source && (
                              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                                addr.source === "api" ? "bg-orange-100 text-orange-800" : "bg-slate-100 text-slate-700"
                              }`}>
                                {addr.source === "api" ? "API" : "Browser"}
                              </span>
                            )}
                            {addr.censusMatched && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                                Census Match
                              </span>
                            )}
                            {addr.googleMatched && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                                Google Match
                              </span>
                            )}
                            {addr.uspsMatched && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800">
                                USPS Match
                              </span>
                            )}
                            {addr.lmiDesignation && (
                              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getLmiColor(addr.lmiDesignation)}`}>
                                {addr.lmiDesignation} Income
                              </span>
                            )}
                            {addr.isLmiTract && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                                LMI Tract
                              </span>
                            )}
                          </div>
                          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-sm text-slate-600">
                            {addr.censusCounty && <span>County: {addr.censusCounty}</span>}
                            {addr.censusState && <span>State: {addr.censusState}</span>}
                            {addr.censusTract && <span>Tract: {addr.censusTract}</span>}
                            {addr.medianHouseholdIncome && <span>Median Income: {formatCurrency(addr.medianHouseholdIncome)}</span>}
                          </div>
                          <div className="flex items-center gap-2 mt-2">
                            <p className="text-xs text-slate-400">
                              {new Date(addr.createdAt).toLocaleString()}
                            </p>
                            {addr.normalizedAddress && (
                              <button
                                onClick={() => toggleHistoryJson(addr.id)}
                                className="inline-flex items-center gap-1 px-2 py-0.5 text-xs text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded transition-colors"
                                data-testid={`button-json-${addr.id}`}
                              >
                                {expandedHistoryJson.has(addr.id) ? (
                                  <>
                                    <ChevronUp className="w-3 h-3" />
                                    Hide JSON
                                  </>
                                ) : (
                                  <>
                                    <ChevronDown className="w-3 h-3" />
                                    Show JSON
                                  </>
                                )}
                              </button>
                            )}
                          </div>
                        </div>
                        <button
                          onClick={() => deleteAddress(addr.id)}
                          className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors"
                          title="Delete"
                          data-testid={`button-delete-${addr.id}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                      {expandedHistoryJson.has(addr.id) && (
                        <div className="mt-3 bg-slate-900 rounded-lg p-4 overflow-x-auto">
                          <pre className="text-xs text-slate-300 font-mono">
                            {JSON.stringify(getNormalizedAddressFromHistory(addr), null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
