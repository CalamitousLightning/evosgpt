document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("chat-form");
    const input = document.getElementById("user_input");
    const messages = document.getElementById("messages");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const userText = input.value.trim();
        if (!userText) return;

        // Show user message instantly
        const userMsg = document.createElement("div");
        userMsg.className = "user-msg";
        userMsg.innerHTML = `<p>${userText}</p>`;
        messages.appendChild(userMsg);

        // Clear input
        input.value = "";

        // Send to Flask backend
        try {
            const res = await fetch("/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ user_input: userText })
            });
            const data = await res.json();

            // Show bot reply
            const botMsg = document.createElement("div");
            botMsg.className = "bot-msg";
            botMsg.innerHTML = `<p>${data.reply}</p>`;
            messages.appendChild(botMsg);

            // Auto-scroll
            messages.scrollTop = messages.scrollHeight;
        } catch (err) {
            console.error("Error:", err);
        }
    });
});
