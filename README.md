# CipherGuard: Secure Covert Communication 🛡️

![image](https://github.com/user-attachments/assets/c68775ef-0c8b-47f6-8df2-8910454e8c24)


---

## 🚀 Overview

CipherGuard is a web-based steganography tool designed for **secure and discreet information transfer**. In an increasingly transparent digital world, where even encrypted communications can reveal metadata patterns, CipherGuard provides an essential layer of **covertness** by embedding secret messages invisibly within ordinary image files. Our aim is to empower individuals and organizations to reclaim their digital privacy.

## ✨ Features

* **Invisible Message Embedding:** Utilizes **Least Significant Bit (LSB) steganography** to hide messages directly within image pixels, making changes visually undetectable.
* **Dual-Layer Security:** Messages are **encrypted (e.g., using AES-256)** *before* being embedded, ensuring both confidentiality and covertness.
* **Intuitive Web Interface:** A user-friendly web application simplifies the complex process of steganography for all users.
* **Cross-Platform Accessibility:** Being web-based, CipherGuard is accessible from any device with a modern browser.
* **Robust Extraction:** Ensures accurate and complete retrieval of hidden messages with the correct password.

## 💡 Why CipherGuard?

Traditional encryption secures your message content, but it doesn't hide the *fact* that you're communicating. In scenarios like **circumventing censorship, protecting sensitive intellectual property, or secure whistleblowing**, merely encrypting isn't enough. CipherGuard ensures your communication exists beyond detection, offering true digital secrecy.

## 🛠️ Technologies Used

* **Backend:** Python 🐍, Flask
* **Frontend:** HTML5, CSS3, JavaScript
* **Image Processing:** Pillow (Python Imaging Library)

## 📦 Installation & Setup (Local Development)

To run CipherGuard locally, follow these steps:

1.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Create a `requirements.txt` file in your project root if you don't have one, listing Flask, Pillow, etc.)*
3.  **Run the Flask application:**
    ```bash
    export FLASK_APP=app.py # Or your main Flask app file
    flask run
    ```
    (On Windows, use `set FLASK_APP=app.py` before `flask run`)

4.  **Access in browser:** Open `http://127.0.0.1:5000` (or the address shown in your terminal) in your web browser.

## 🚀 Usage

### Embedding a Message:

1.  Navigate to the "Steganography Module" (or your main page).
2.  Upload a carrier image (e.g., PNG, BMP for best results).
3.  Enter your secret message into the text area.
4.  Provide a strong password for encryption.
5.  Click "Embed Message" and download the generated stego-image.

### Extracting a Message:

1.  Navigate to the "Steganography Module" (or the extraction section).
2.  Upload the stego-image.
3.  Enter the exact password used during embedding.
4.  Click "Extract Message" to reveal the hidden content.

## 👨‍💻 Contributing

We welcome contributions to CipherGuard! If you have suggestions, bug reports, or want to contribute code, please feel free to:

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## 📜 License

This project is licensed under the **MIT License** - see the `LICENSE` file for details.
*(Replace with your actual license if different, and ensure you have a `LICENSE` file in your repo.)*

## 📞 Contact

For any questions or collaborations, reach out to:

* **Email** - [officialanindyamaity@gmail.com](mailto:officialanindyamaity@gmail.com)

---

**CipherGuard: Your Digital Secrecy, Our Priority.**
