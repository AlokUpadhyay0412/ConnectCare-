document.addEventListener("DOMContentLoaded", () => {
    const chatBox = document.getElementById("chat-box");
    const userInput = document.getElementById("user-input");
    const sendBtn = document.getElementById("send-btn");
    const typingIndicator = document.getElementById("typing-indicator");

    let conversationContext = "initial"; // Manages the state of the conversation

    // --- Core Functions ---
    const addMessage = (content, sender) => {
        const messageWrapper = document.createElement("div");
        messageWrapper.className = `message ${sender}-message`;
        const messageContent = document.createElement("div");
        messageContent.className = "message-content";
        messageContent.innerHTML = content;
        messageWrapper.appendChild(messageContent);
        chatBox.appendChild(messageWrapper);
        chatBox.scrollTop = chatBox.scrollHeight;
    };

    const showTypingIndicator = (show) => {
        typingIndicator.style.display = show ? "flex" : "none";
        if (show) chatBox.scrollTop = chatBox.scrollHeight;
    };

    const handleUserInput = () => {
        const userMessage = userInput.value;
        if (userMessage.trim() === "") return;

        addMessage(userMessage, "user");
        userInput.value = "";
        
        showTypingIndicator(true);

        setTimeout(() => {
            const botResponse = getAIResponse(userMessage);
            showTypingIndicator(false);
            addMessage(botResponse.text, "bot");
            conversationContext = botResponse.newContext; // Update context
        }, 1200);
    };

    // --- AI Response Logic ---
    const getAIResponse = (userMessage) => {
        const msg = userMessage.toLowerCase().trim();

        // Global commands that reset context
        if (msg.includes("start over") || msg.includes("main menu")) {
            return {
                text: "Of course, let's start over. How can I assist you? You can ask me about our <b>services, booking process,</b> or <b>pricing</b>.",
                newContext: "initial"
            };
        }
        if (msg.includes("bye") || msg.includes("thank you") || msg.includes("thanks")) {
            return {
                text: "You're most welcome! Please feel free to reach out if you need anything else. Stay safe!",
                newContext: "end"
            };
        }

        // --- Contextual Responses ---
        switch (conversationContext) {
            case "awaiting_service_choice":
                if (msg.includes("bls") || msg.includes("basic")) {
                    return {
                        text: "Great choice. Our <b>Basic Life Support (BLS)</b> ambulances are equipped with essential medical equipment like oxygen cylinders and first aid kits, staffed by certified paramedics. They are ideal for patients with stable conditions. <br><br>Would you like to know about <b>ALS</b> or <b>Air Ambulances</b> next?",
                        newContext: "awaiting_service_choice"
                    };
                }
                if (msg.includes("als") || msg.includes("advanced")) {
                    return {
                        text: "Excellent. The <b>Advanced Life Support (ALS)</b> ambulances are essentially mobile ICUs. They have ventilators, ECG machines, and other critical care equipment for patients who need intensive monitoring. <br><br>I can also tell you about our <b>BLS</b> or <b>Air Ambulance</b> services.",
                        newContext: "awaiting_service_choice"
                    };
                }
                 if (msg.includes("air")) {
                    return {
                        text: "Our <b>Air Ambulance</b> service is for long-distance or critical-time transfers. We coordinate with aviation partners to move patients swiftly and safely across cities. <br><br>Is there another service like <b>BLS</b> or <b>ALS</b> you'd like to explore?",
                        newContext: "awaiting_service_choice"
                    };
                }
                break;
            
            case "awaiting_booking_step":
                 if (msg.includes("documents") || msg.includes("prepare")) {
                    return {
                        text: "A very good question. Please have the patient's ID, a doctor's referral note (if available), and any relevant medical reports handy. This helps us streamline the admission process at the hospital. <br><br>Can I help with anything else about booking?",
                        newContext: "awaiting_booking_step"
                    };
                 }
                break;
        }

        // --- Initial Keyword Detection (If no specific context) ---
        if (msg.includes("service") || msg.includes("offer")) {
            return {
                text: "We provide a comprehensive range of emergency transport solutions. This includes <b>BLS (Basic Life Support)</b>, <b>ALS (Advanced Life Support)</b>, and <b>Air Ambulance</b> services. <br><br>Which one would you like to know more about?",
                newContext: "awaiting_service_choice"
            };
        }
        if (msg.includes("book") || msg.includes("ambulance")) {
            return {
                text: "I can guide you through the booking process. The quickest way is to log in to our website and fill out the booking form. Our dispatch team confirms the details via a call and sends the nearest ambulance. <br><br>Would you like to know what <b>documents to prepare</b>?",
                newContext: "awaiting_booking_step"
            };
        }
        if (msg.includes("price") || msg.includes("cost")) {
            return {
                text: "Pricing is calculated based on the type of ambulance required, the distance to be covered, and any special equipment used. For a precise quote, please use the booking form on our website. This ensures complete transparency.",
                newContext: "initial"
            };
        }
        if (msg.includes("fast") || msg.includes("time") || msg.includes("arrive")) {
            return {
                text: "Our goal is to reach you as quickly as possible. In metro areas like <b>Noida</b>, our average arrival time is under <b>15 minutes</b>, thanks to our strategically located fleet.",
                newContext: "initial"
            };
        }

        // --- Default Fallback Response ---
        return {
            text: "I'm sorry, my systems are still learning. I didn't quite understand that. Could you perhaps rephrase? You can always ask me about <b>'services'</b>, <b>'how to book'</b>, or <b>'pricing'</b>.",
            newContext: "initial"
        };
    };

    // --- Event Listeners and Initial Greeting ---
    sendBtn.addEventListener("click", handleUserInput);
    userInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") handleUserInput();
    });

    const initialGreeting = () => {
        showTypingIndicator(true);
        setTimeout(() => {
            showTypingIndicator(false);
            addMessage("Hello! I am the ResQNow AI assistant, here to help you 24/7. How may I assist you today?", "bot");
        }, 1500);
    };

    initialGreeting();
});