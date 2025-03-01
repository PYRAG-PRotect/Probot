const crypto = require("crypto");

const APP_ID = process.env.APP_ID;
const PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, "\n");
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Generate JWT for GitHub App Authentication
function generateJWT() {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64");
  const payload = Buffer.from(
    JSON.stringify({
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 600,
      iss: APP_ID,
    })
  ).toString("base64");

  const signature = crypto.createSign("RSA-SHA256").update(`${header}.${payload}`).sign(PRIVATE_KEY, "base64");

  return `${header}.${payload}.${signature}`;
}

// Get Installation ID for the repo owner
async function getInstallationId(owner) {
  const jwt = generateJWT();
  const url = `https://api.github.com/app/installations`;
  
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
    },
  });

  if (!response.ok) throw new Error(`Failed to fetch installations: ${response.statusText}`);
  
  const installations = await response.json();
  const installation = installations.find((inst) => inst.account.login === owner);
  
  if (!installation) throw new Error(`No installation found for ${owner}`);
  return installation.id;
}

// Get Installation Token
async function getInstallationToken(owner) {
  const installationId = await getInstallationId(owner);
  const jwt = generateJWT();
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
    },
  });

  if (!response.ok) throw new Error(`Failed to get installation token: ${response.statusText}`);
  
  const data = await response.json();
  return data.token;
}

// Verify Webhook Signature
function verifySignature(req, rawBody) {
  const signature = req.headers["x-hub-signature-256"];
  if (!signature) return false;

  const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
  hmac.update(rawBody);
  const expectedSignature = `sha256=${hmac.digest("hex")}`;

  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
}

// Fetch PR Files
async function getPRFiles(repo, owner, prNumber, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
    },
  });

  if (!response.ok) throw new Error(`Failed to fetch PR files: ${response.statusText}`);
  
  return await response.json();
}

const SECURITY_PATTERNS = {
  sensitiveData: {
    pattern:
      /(password|secret|token|key|api[_-]?key|credentials?|auth_token)[\s]*[=:]\s*['"`][^'"`]*['"`]/i,
    score: -20,
    message: "Possible sensitive data exposure",
  },
  sqlInjection: {
    pattern:
      /(\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)|(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*['"]\s*\+)/i,
    score: -15,
    message: "Potential SQL injection vulnerability",
  },
  commandInjection: {
    pattern:
      /(eval\s*\(|exec\s*\(|execSync|spawn\s*\(|fork\s*\(|child_process|shelljs|\.exec\(.*\$\{)/i,
    score: -25,
    message: "Potential command injection risk",
  },
  insecureConfig: {
    pattern:
      /(allowAll|disableSecurity|noValidation|validateRequest:\s*false|security:\s*false)/i,
    score: -10,
    message: "Potentially insecure configuration",
  },
  xssVulnerability: {
    pattern:
      /(innerHTML|outerHTML|document\.write|eval\(.*\$\{|dangerouslySetInnerHTML)/i,
    score: -15,
    message: "Potential XSS vulnerability",
  },
  unsafeDeserialize: {
    pattern:
      /(JSON\.parse\(.*\$\{|eval\(.*JSON|deserialize\(.*user|fromJSON\(.*input)/i,
    score: -20,
    message: "Unsafe deserialization of data",
  },
  maliciousPackages: {
    pattern:
      /"dependencies":\s*{[^}]*"(evil-|malicious-|hack-|unsafe-|vulnerable-)/i,
    score: -30,
    message: "Potentially malicious package dependency",
  },
  cryptoMining: {
    pattern: /(crypto\.?miner|mineCrypto|coinHive|webMining|monero\.?miner)/i,
    score: -50,
    message: "Potential cryptocurrency mining code",
  },
  dataExfiltration: {
    pattern:
      /(\.upload\(.*\$\{|fetch\(['"`]https?:\/\/[^\/]+\.[^\/]+\/[^\/]+\?.*\$\{)/i,
    score: -40,
    message: "Potential data exfiltration attempt",
  },
  obfuscatedCode: {
    pattern:
      /(eval\(atob|eval\(decode|String\.fromCharCode.*\)\.call\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){10,}/i,
    score: -35,
    message: "Heavily obfuscated code detected",
  },
  suspiciousUrls: {
    pattern:
      /https?:\/\/(?:[^\/]+\.)?(?:xyz|tk|ml|ga|cf|gq|pw|top|club)\/[^\s"']+/i,
    score: -15,
    message: "Suspicious URL domain detected",
  },
  hardcodedIPs: {
    pattern:
      /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/,
    score: -5,
    message: "Hardcoded IP address detected",
  },
  debugCode: {
    pattern: /(console\.log\(|debugger|alert\()/i,
    score: -5,
    message: "Debug code found in production",
  },
};

// Analyze Security of PR Files
async function analyzeSecurity(files) {
  let totalScore = 100;
  let findings = [];

  for (const file of files) {
    const response = await fetch(file.raw_url);
    const content = await response.text();

    for (const [key, { pattern, score, message }] of Object.entries(SECURITY_PATTERNS)) {
      if (pattern.test(content)) {
        totalScore += score;
        findings.push(`🔍 **${file.filename}** - ${message}`);
      }
    }
  }

  let level = "monitor";
  if (totalScore < 60) level = "review";
  if (totalScore < 40) level = "warn";
  if (totalScore < 20) level = "block";

  return { score: totalScore, level, findings };
}

// Post Comment
async function postComment(repo, owner, prNumber, comment, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments`;

  await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ body: comment }),
  });
}

// Close PR
async function closePR(repo, owner, prNumber, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}`;
  
  await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ state: "closed" }),
  });
}

// Block User
async function blockUser(owner, username, token) {
  const url = `https://api.github.com/orgs/${owner}/blocks/${username}`;

  await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
}

// Webhook Handler
export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  let rawBody = "";
  req.on("data", (chunk) => (rawBody += chunk));
  req.on("end", async () => {
    if (!verifySignature(req, rawBody)) {
      console.error("Signature verification failed!");
      return res.status(401).json({ error: "Invalid signature" });
    }

    const event = req.headers["x-github-event"];
    if (event !== "pull_request") return res.status(200).json({ message: "Non-PR event ignored" });

    const { action, pull_request } = req.body;
    const prNumber = pull_request.number;
    const repo = pull_request.base.repo.name;
    const owner = pull_request.base.repo.owner.login;
    const username = pull_request.user.login;

    console.log(`PR #${prNumber} ${action} in ${owner}/${repo}`);

    if (action === "opened" || action === "synchronize") {
      try {
        const token = await getInstallationToken(owner);
        const files = await getPRFiles(repo, owner, prNumber, token);
        const { score, level, findings } = await analyzeSecurity(files);

        let body = `## 🔍 Security Analysis  
**Security Score:** ${score}/100  
`;
        if (findings.length) body += findings.join("\n") + "\n\n";

        switch (level) {
          case "block":
            body += "⛔ **PR BLOCKED**: Critical security concerns detected.";
            await blockUser(owner, username, token);
            await closePR(repo, owner, prNumber, token);
            break;
          case "warn":
            body += "⚠️ **WARNING**: Review security issues before merging.";
            await closePR(repo, owner, prNumber, token);
            break;
          case "review":
            body += "👀 **REVIEW**: Security concerns detected, review required.";
            break;
          default:
            body += "ℹ️ **MONITOR**: No major issues detected.";
            break;
        }

        await postComment(repo, owner, prNumber, body, token);
      } catch (error) {
        console.error("❌ Error processing PR:", error.message);
      }
    }

    res.status(200).json({ message: "Security check completed" });
  });
}
