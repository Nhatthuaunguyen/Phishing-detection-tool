import React, { useState, useEffect } from 'react';
import { 
  View, 
  Text, 
  StyleSheet, 
  Modal, 
  TouchableOpacity, 
  TextInput, 
  ActivityIndicator, 
  ScrollView, 
  Linking, 
  SafeAreaView 
} from 'react-native';

// Local Backend API (For identical, highly accurate ML + WHOIS + LLM results matching the web plugin)
const BACKEND_API = "http://127.0.0.1:5000/analyze";
// Production Backend API (Serverless Vercel sandbox - may lack WHOIS access or ML models)
// const BACKEND_API = "https://phising-detection-web-tool.vercel.app/analyze";

// 20 suspicious/phishing URLs for simulation
const SUSPICIOUS_LINKS = [
  "http://1.2.3.4/paypal-login",
  "http://secure-paypal-verify.com/account/login",
  "http://appleid-apple-support.xyz/verify",
  "http://amazon-order-confirm.net/tracking?id=9938",
  "http://netflix-billing-update.info/payment",
  "http://bankofamerica-secure.ml/login",
  "http://micros0ft-account-alert.com/verify",
  "http://google-security-alert.tk/signinhelp",
  "http://fb-login-checkpoint.xyz/identity",
  "http://dhl-delivery-tracking.club/parcel/verify",
  "http://irs-tax-refund.net/claim-refund",
  "http://coinbase-wallet-verify.info/2fa",
  "http://wells-fargo-alert.ml/account-suspended",
  "http://instagram-support-verify.com/appeal",
  "http://chase-bank-secure.xyz/login-confirm",
  "http://192.168.1.1:8080/admin/steal-session",
  "http://bit.ly/3xPh1sh-p4ypal",
  "http://dropbox-shared-document.net/view?token=abc123",
  "http://zoom-meeting-invite.xyz/join?id=99999",
  "http://steam-trade-offer-confirm.ml/login",
];

export default function App() {
  const [searchQuery, setSearchQuery] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [warningVisible, setWarningVisible] = useState(false);
  const [blockedUrl, setBlockedUrl] = useState(null);
  const [reasons, setReasons] = useState([]);
  const [verdict, setVerdict] = useState(null); // 'safe' | 'unsafe'
  const [simulatedLink, setSimulatedLink] = useState(null);

  // Simulate catching an Intent or Deep Link from OS
  useEffect(() => {
    // 1. App handles initial URL if opened via link
    Linking.getInitialURL().then(url => {
      if (url) handleIncomingURL(url);
    });

    // 2. App handles URLs received while in foreground/background
    const subscription = Linking.addEventListener('url', ({ url }) => {
      handleIncomingURL(url);
    });

    return () => subscription.remove();
  }, []);

  // Client-side heuristics fallback scanner
  const executeClientHeuristics = (url) => {
    const localReasons = [];
    let score = 0;
    let hostname = "";
    
    try {
      const urlObj = new URL(url);
      hostname = urlObj.hostname.toLowerCase();
      
      // Heuristic 1: Insecure connection
      if (urlObj.protocol !== "https:") {
        localReasons.push("Insecure connection (HTTP instead of HTTPS)");
        score += 30;
      }

      // Heuristic 2: Raw IP host
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        localReasons.push("Host domain displays as raw numeric IP address");
        score += 50;
      }

      // Heuristic 3: URL length
      if (url.length > 95) {
        localReasons.push(`Atypical URL complexity (${url.length} characters)`);
        score += 15;
      }

      // Heuristic 4: Suspicious Keywords
      const phishingKeywords = ["secure", "signin", "login", "update", "verify", "webscr", "account", "banking", "free"];
      const matchedKeywords = phishingKeywords.filter(k => url.toLowerCase().includes(k));
      if (matchedKeywords.length > 0) {
        localReasons.push(`Contains suspicious keywords: [${matchedKeywords.join(", ")}]`);
        score += matchedKeywords.length * 10;
      }

      // Heuristic 5: Excessive dots
      const dotsCount = hostname.split(".").length - 1;
      if (dotsCount > 3) {
        localReasons.push("Unusual nesting of subdomains (excessive dots)");
        score += 20;
      }

    } catch (e) {
      localReasons.push("URL structure parsed as malformed or corrupt");
      score = 40;
    }

    return {
      is_unsafe: score >= 30,
      reasons: localReasons
    };
  };

  const handleIncomingURL = async (url) => {
    if (!url) return;
    setIsScanning(true);

    try {
      console.log(`Analyzing URL: ${url}`);
      
      // Set short 4-second timeout for server check
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const response = await fetch(BACKEND_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Server returned error code: ${response.status}`);
      }

      const data = await response.json();
      console.log("Analysis Result:", data);

      setIsScanning(false);
      setBlockedUrl(url);

      const finalScore = data.final_risk_score !== undefined ? data.final_risk_score : (data.score || 0);
      const isUnsafe = data.is_unsafe !== undefined ? data.is_unsafe : (finalScore > 35);
      const rawReasons = data.top_reasons || data.reasons || [data.user_explanation] || [];
      
      const reasonsList = rawReasons.filter(r => r && String(r).trim().length > 0);
      setReasons(reasonsList.length > 0 ? reasonsList : (isUnsafe ? ["Website exhibits suspicious phishing layout signatures."] : ["URL contains standard secure domain structures."]));
      setVerdict(isUnsafe ? 'unsafe' : 'safe');
      setWarningVisible(true);

    } catch (err) {
      console.warn("Backend connection failed. Running offline heuristics...", err);
      setIsScanning(false);
      
      // Run local scanner fallback
      const fallbackResult = executeClientHeuristics(url);
      setBlockedUrl(url);
      setReasons([...fallbackResult.reasons, "Backend Offline - Checked via local heuristic scanner."]);
      setVerdict(fallbackResult.is_unsafe ? 'unsafe' : 'safe');
      setWarningVisible(true);
    }
  };

  // Perform Manual Input Search
  const handleSearch = () => {
    const query = searchQuery.trim();
    if (query) {
      // Normalize URL scheme if omitted
      let formattedUrl = query;
      if (!/^https?:\/\//i.test(query)) {
        formattedUrl = "http://" + query;
      }
      handleIncomingURL(formattedUrl);
    }
  };

  const handleProceed = () => {
    setWarningVisible(false);
    if (blockedUrl) {
      Linking.openURL(blockedUrl); // Force open safely in external browser
    }
  };

  const handleCloseModal = () => {
    setWarningVisible(false);
    setBlockedUrl(null);
    setReasons([]);
    setVerdict(null);
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.logoContainer}>
        <Text style={styles.title}>AI Security Checker</Text>
        <Text style={styles.sub}>Real-time Link Scanner & Shield</Text>
      </View>

      {/* Manual Search and Input Section */}
      <View style={styles.searchContainer}>
        <TextInput
          style={styles.searchInput}
          placeholder="Type or paste a URL to scan..."
          placeholderTextColor="#71717a"
          value={searchQuery}
          onChangeText={setSearchQuery}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          spellCheck={false}
        />
        <TouchableOpacity style={styles.searchBtn} onPress={handleSearch} activeOpacity={0.7}>
          <Text style={styles.searchBtnText}>Scan</Text>
        </TouchableOpacity>
      </View>

      {/* Loading Indicator */}
      {isScanning && (
        <View style={styles.loaderContainer}>
          <ActivityIndicator size="large" color="#6366f1" />
          <Text style={styles.loaderText}>Analyzing Link Security...</Text>
        </View>
      )}

      {/* Simulation Trigger Section */}
      <View style={styles.simulationBox}>
        <Text style={styles.simHeader}>Quick-Test Simulation Feed</Text>
        <TouchableOpacity
          style={styles.simulateBtn}
          activeOpacity={0.8}
          onPress={() => {
            const randomLink = SUSPICIOUS_LINKS[Math.floor(Math.random() * SUSPICIOUS_LINKS.length)];
            setSimulatedLink(randomLink);
            handleIncomingURL(randomLink);
          }}
        >
          <Text style={styles.btnText}>Simulate Intercepting Click</Text>
        </TouchableOpacity>
        
        {simulatedLink && (
          <Text style={styles.simulatedLinkText} numberOfLines={1}>
            🔗 {simulatedLink}
          </Text>
        )}
      </View>

      {/* Safe and Unsafe Verdict Popup Modal */}
      <Modal visible={warningVisible} transparent animationType="slide" onRequestClose={handleCloseModal}>
        <View style={styles.modalBg}>
          <View style={[
            styles.modalCard,
            verdict === 'safe' ? styles.modalCardSafe : styles.modalCardUnsafe
          ]}>
            {/* Top URL Display Area */}
            <View style={styles.topUrlCard}>
              <Text style={styles.topUrlLabel}>TARGET URL</Text>
              <Text style={styles.topUrlText} numberOfLines={2}>{blockedUrl}</Text>
            </View>

            {/* Verdict Indicator */}
            {verdict === 'unsafe' ? (
              <View style={styles.verdictContainer}>
                <View style={styles.verdictIconBgUnsafe}>
                  <Text style={styles.verdictIcon}>⚠️</Text>
                </View>
                <Text style={styles.verdictTitleUnsafe}>Suspicious Link Blocked</Text>
                <Text style={styles.verdictSub}>
                  Our engine flagged this interaction as potentially dangerous. Visiting it could result in identity theft.
                </Text>
              </View>
            ) : (
              <View style={styles.verdictContainer}>
                <View style={styles.verdictIconBgSafe}>
                  <Text style={styles.verdictIcon}>🛡️</Text>
                </View>
                <Text style={styles.verdictTitleSafe}>Secure Link Verified</Text>
                <Text style={styles.verdictSub}>
                  No active phishing signatures or threat patterns detected. This website appears standard and safe to open.
                </Text>
              </View>
            )}

            {/* Reasons / Risk Assessment Box */}
            <View style={styles.reasonBox}>
              <Text style={[
                styles.reasonTitle,
                verdict === 'safe' ? styles.reasonTitleSafe : styles.reasonTitleUnsafe
              ]}>
                {verdict === 'safe' ? 'TRUST FACTORS' : 'SECURITY ANALYSIS'}
              </Text>
              
              <ScrollView 
                style={styles.reasonsScroll} 
                contentContainerStyle={styles.reasonsScrollContent}
                showsVerticalScrollIndicator={true}
              >
                {reasons.map((r, i) => (
                  <Text key={i} style={styles.reasonItem}>
                    {verdict === 'safe' ? '✓' : '•'} {r}
                  </Text>
                ))}
              </ScrollView>
            </View>

            {/* Action Buttons */}
            <View style={styles.buttons}>
              {verdict === 'unsafe' ? (
                <>
                  <TouchableOpacity style={styles.backBtn} onPress={handleCloseModal} activeOpacity={0.8}>
                    <Text style={styles.backBtnText}>Back to Safety</Text>
                  </TouchableOpacity>

                  <TouchableOpacity style={styles.proceedBtn} onPress={handleProceed} activeOpacity={0.8}>
                    <Text style={styles.proceedBtnText}>Proceed Anyway (Unsafe)</Text>
                  </TouchableOpacity>
                </>
              ) : (
                <>
                  <TouchableOpacity style={styles.openBtn} onPress={handleProceed} activeOpacity={0.8}>
                    <Text style={styles.openBtnText}>Open Website</Text>
                  </TouchableOpacity>

                  <TouchableOpacity style={styles.closeBtn} onPress={handleCloseModal} activeOpacity={0.8}>
                    <Text style={styles.closeBtnText}>Close Report</Text>
                  </TouchableOpacity>
                </>
              )}
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { 
    flex: 1, 
    justifyContent: 'space-between', 
    alignItems: 'center', 
    backgroundColor: '#090d16',
    paddingVertical: 30,
    paddingHorizontal: 20
  },
  logoContainer: {
    alignItems: 'center',
    marginTop: 40,
  },
  title: { 
    fontSize: 26, 
    fontWeight: 'bold', 
    color: '#ffffff',
    letterSpacing: -0.5,
  },
  sub: { 
    color: '#9ca3af', 
    marginTop: 8, 
    fontSize: 14,
    fontWeight: '400'
  },
  
  // Search Bar UI
  searchContainer: {
    flexDirection: 'row',
    backgroundColor: 'rgba(255, 255, 255, 0.04)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.08)',
    borderRadius: 12,
    padding: 4,
    alignItems: 'center',
    width: '100%',
    marginVertical: 20,
  },
  searchInput: {
    flex: 1,
    color: '#f3f4f6',
    fontSize: 14,
    paddingHorizontal: 12,
    height: 48,
  },
  searchBtn: {
    backgroundColor: '#6366f1',
    borderRadius: 8,
    paddingHorizontal: 16,
    height: 40,
    justifyContent: 'center',
    alignItems: 'center',
  },
  searchBtnText: {
    color: '#ffffff',
    fontWeight: '600',
    fontSize: 14,
  },

  // Loader UI
  loaderContainer: {
    marginVertical: 10,
    alignItems: 'center',
  },
  loaderText: {
    color: '#a1a1aa',
    fontSize: 12,
    marginTop: 8,
  },

  // Simulation UI
  simulationBox: {
    width: '100%',
    backgroundColor: 'rgba(255, 255, 255, 0.02)',
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.05)',
    marginBottom: 40,
  },
  simHeader: {
    color: '#9ca3af',
    fontSize: 12,
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    textAlign: 'center',
    marginBottom: 12,
  },
  simulateBtn: { 
    backgroundColor: 'rgba(255, 255, 255, 0.05)', 
    padding: 14, 
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.08)',
  },
  btnText: { 
    color: '#ffffff', 
    fontWeight: '600', 
    textAlign: 'center',
    fontSize: 14,
  },
  simulatedLinkText: { 
    color: '#f87171', 
    marginTop: 12, 
    fontSize: 12, 
    textAlign: 'center',
    fontWeight: '400',
  },

  // Dynamic Modals UI
  modalBg: { 
    flex: 1, 
    backgroundColor: 'rgba(0,0,0,0.85)', 
    justifyContent: 'flex-end' 
  },
  modalCard: {
    padding: 24,
    borderTopLeftRadius: 28,
    borderTopRightRadius: 28,
    borderWidth: 1,
  },
  modalCardUnsafe: {
    backgroundColor: '#160B0E',
    borderColor: 'rgba(239, 68, 68, 0.25)',
  },
  modalCardSafe: {
    backgroundColor: '#0B1612',
    borderColor: 'rgba(16, 185, 129, 0.25)',
  },

  // Top URL display card
  topUrlCard: {
    backgroundColor: 'rgba(255, 255, 255, 0.03)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.06)',
    borderRadius: 14,
    padding: 12,
    marginBottom: 20,
  },
  topUrlLabel: {
    fontSize: 9,
    fontWeight: '700',
    color: '#9ca3af',
    letterSpacing: 0.8,
    marginBottom: 4,
  },
  topUrlText: {
    fontSize: 13,
    color: '#e4e4e7',
    fontWeight: '400',
  },

  // Verdict UI
  verdictContainer: {
    alignItems: 'center',
    marginBottom: 20,
  },
  verdictIconBgUnsafe: {
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 12,
  },
  verdictIconBgSafe: {
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.3)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 12,
  },
  verdictIcon: { 
    fontSize: 22, 
  },
  verdictTitleUnsafe: { 
    fontSize: 20, 
    fontWeight: 'bold', 
    color: '#ef4444', 
    textAlign: 'center', 
    marginBottom: 8 
  },
  verdictTitleSafe: { 
    fontSize: 20, 
    fontWeight: 'bold', 
    color: '#10b981', 
    textAlign: 'center', 
    marginBottom: 8 
  },
  verdictSub: { 
    color: '#9ca3af', 
    textAlign: 'center', 
    fontSize: 13,
    lineHeight: 18,
    paddingHorizontal: 10,
  },

  // Reason Box UI
  reasonBox: { 
    backgroundColor: 'rgba(0, 0, 0, 0.25)', 
    padding: 16, 
    borderRadius: 14, 
    marginBottom: 24, 
    borderWidth: 1, 
    borderColor: 'rgba(255, 255, 255, 0.05)',
  },
  reasonTitle: { 
    fontWeight: '700', 
    fontSize: 11, 
    letterSpacing: 0.8,
    marginBottom: 10 
  },
  reasonTitleUnsafe: {
    color: '#fca3a3',
  },
  reasonTitleSafe: {
    color: '#a3fca3',
  },
  reasonsScroll: {
    maxHeight: 110,
  },
  reasonsScrollContent: {
    paddingBottom: 4,
  },
  reasonItem: { 
    color: '#d1d5db', 
    marginBottom: 6, 
    fontSize: 12.5,
    lineHeight: 16,
  },

  // Dynamic Buttons
  buttons: { 
    flexDirection: 'column', 
    gap: 12 
  },
  backBtn: { 
    backgroundColor: '#ef4444', 
    paddingVertical: 14, 
    borderRadius: 10, 
    alignItems: 'center',
    shadowColor: '#ef4444',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 3,
  },
  backBtnText: { 
    color: '#ffffff', 
    fontWeight: 'bold', 
    fontSize: 15 
  },
  proceedBtn: { 
    backgroundColor: 'transparent', 
    paddingVertical: 14, 
    borderRadius: 10, 
    alignItems: 'center', 
    borderWidth: 1, 
    borderColor: 'rgba(255, 255, 255, 0.15)' 
  },
  proceedBtnText: { 
    color: '#9ca3af', 
    fontWeight: '600',
    fontSize: 13,
  },

  openBtn: { 
    backgroundColor: '#10b981', 
    paddingVertical: 14, 
    borderRadius: 10, 
    alignItems: 'center',
    shadowColor: '#10b981',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 3,
  },
  openBtnText: { 
    color: '#ffffff', 
    fontWeight: 'bold', 
    fontSize: 15 
  },
  closeBtn: { 
    backgroundColor: 'transparent', 
    paddingVertical: 14, 
    borderRadius: 10, 
    alignItems: 'center', 
    borderWidth: 1, 
    borderColor: 'rgba(255, 255, 255, 0.15)' 
  },
  closeBtnText: { 
    color: '#9ca3af', 
    fontWeight: '600',
    fontSize: 13,
  }
});
