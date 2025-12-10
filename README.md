# Overview

- Discovers reflected parameters (even when they’re hidden behind JSONP callbacks or weird routing).
- Uses a Random Forest model to separate real DOM XSS sinks from the endless sea of false positives.

![Tela01](https://github.com/user-attachments/assets/0237ebef-97d1-4365-8019-c437f9ea276b) ![tela02](https://github.com/user-attachments/assets/7e324db7-4471-4277-8e52-5bc7e81f904e)

# Installation

- Install dependencies with:

        pip install requests ttkbootstrap scikit-learn joblib numpy

- Then run the scanner:

        python vulnforge.py

- That’s it. No config files, no complex setup. Just run it and start hunting.
  
- On first launch, VulnForge creates a data directory in your system's standard app location:

        Windows: %APPDATA%\VulnForge
        macOS/Linux: ~/.vulnforge

- This stores trained models and scan logs.

# Limitations Worth Knowing

- This tool focuses specifically on DOM-based XSS. It won't catch reflected or stored XSS that doesn't involve DOM manipulation. The machine learning component needs diverse training data to reach peak accuracy scanning only similar applications limits its learning potential. VulnForge analyzes HTTP responses, but it doesn't execute JavaScript or simulate browser behavior. Some DOM-based vulnerabilities that trigger only through complex client-side interactions might slip through.

## Disclaimer

- VulnForge is a security testing tool. Use it only on systems you own or have explicit written permission to test. The developer of this tool is not responsible for its misuse.
