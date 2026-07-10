// checks.js
// Kết nối tới Backend Python để xử lý logic (AI + Rules)

const BACKEND_API = "http://127.0.0.1:5000/analyze";

async function checkURL(url) {
    try {
        console.log("Sending to AI Backend...", url);
        
        // 1. Gửi URL về Python Backend
        const response = await fetch(BACKEND_API, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();
        console.log("AI Result:", data);

        // 2. Xử lý kết quả trả về từ Backend
        const score = data.final_risk_score !== undefined ? data.final_risk_score : 0;
        const reasons = data.top_reasons || data.reasons || [data.user_explanation] || ["Suspicious website detected"];
        
        return {
            is_unsafe: data.is_unsafe,
            reasons: reasons,
            score: score
        };

    } catch (error) {
        console.error("Backend Connection Failed:", error);
        
        // --- FAIL-SAFE (DỰ PHÒNG) ---
        // Nếu Server Python chưa bật hoặc bị lỗi, ta kiểm tra sơ bộ tại Client
        // để tránh chặn nhầm hoặc bỏ lọt lỗi cơ bản.
        
        const fallbackReasons = [];
        let score = 0;
        
        // Kiểm tra HTTP cơ bản nếu không kết nối được server
        if (!url.startsWith("https")) {
            fallbackReasons.push("Warning: Backend unavailable & Connection is not secure (HTTP)");
            score = 30;
        }

        return {
            is_unsafe: fallbackReasons.length > 0,
            reasons: fallbackReasons,
            score: score
        };
    }
}