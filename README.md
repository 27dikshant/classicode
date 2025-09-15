# ClassiCode - Enterprise File Classification & DLP

[![Visual Studio Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/dikshant.classicode?style=flat-square&logo=visual-studio-code)](https://marketplace.visualstudio.com/items?itemName=dikshant.classicode)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

> **Enterprise-grade security extension that prevents code leakage through automated file classification and data loss prevention.**

ClassiCode seamlessly integrates into your development workflow, providing intelligent file classification with permanent metadata storage and comprehensive protection policies. Perfect for security-conscious teams and organizations requiring DSPM compliance.

## 🛡️ Key Features

### **Automated File Classification**
- **Four Security Levels**: Public, Internal, Confidential, Personal
- **Permanent Storage**: Classifications stored in file metadata (xattrs) that persist even if comments are removed
- **Visual Indicators**: Color-coded watermarks and badges in the editor
- **One-Click Classification**: Right-click context menu for instant file classification

### **Data Loss Prevention (DLP)**
- **Classification-Aware Protection**: Different security policies based on file sensitivity
- **Clipboard Protection**: Automatic clipboard clearing for confidential content
- **File Operation Monitoring**: Prevents unauthorized copying, cutting, and duplication
- **Real-time Alerts**: Immediate warnings for policy violations

### **Enterprise Compliance**
- **DSPM Integration**: Machine-readable metadata for Data Security Posture Management tools
- **Integrity Verification**: Cryptographic hashing to detect tampering
- **Audit Trail**: Complete logging of classification changes and security events
- **Backup Protection**: Multiple storage locations ensure classification persistence

## 🚀 Quick Start

1. **Install ClassiCode** from the VS Code Marketplace
2. **Right-click any file** in the Explorer
3. **Select "Classify File (Permanent)"**
4. **Choose classification level**: Public, Internal, Confidential, or Personal
5. **Automatic protection** activates based on classification

## 📊 Classification Levels

| Level | Description | Protection Level | Use Cases |
|-------|-------------|------------------|-----------|
| **🟢 Public** | Open source, public documentation | None | README files, public APIs |
| **🟡 Internal** | Internal company use | Warnings | Business logic, internal docs |
| **🔴 Confidential** | Sensitive business data | Full Protection | API keys, customer data |
| **🟣 Personal** | Personal information | Moderate Protection | Personal notes, drafts |

## 🔒 Protection Policies

### **Confidential Files** (🔴 Full Protection)
- ❌ **Block**: Copy, Cut, Duplicate, Rename, Save As
- 🧹 **Clipboard**: Automatic clearing of copied confidential content
- 👀 **Monitoring**: File system watcher prevents unauthorized duplication
- 💧 **Watermarks**: Persistent visual indicators (cannot be disabled)

### **Internal Files** (🟡 Warnings)
- ⚠️ **Alerts**: Warnings for external sharing operations
- 📋 **Clipboard**: Monitored but not automatically cleared
- 💧 **Watermarks**: Configurable visual indicators

### **Personal Files** (🟣 Moderate Protection)
- ⚠️ **Alerts**: Warnings for sharing operations
- 💧 **Watermarks**: Optional visual indicators

### **Public Files** (🟢 No Restrictions)
- ✅ **Full Access**: No limitations on file operations
- 💧 **Watermarks**: Optional visual indicators

## 🛠️ Installation

### Via VS Code Marketplace
1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X`)
3. Search for "ClassiCode"
4. Click **Install**

### Via Command Line
```bash
code --install-extension dikshant.classicode
```

### Manual Installation
1. Download the `.vsix` file from releases
2. Run `code --install-extension classicode-1.0.0.vsix`

## ⚙️ Configuration

Access settings via `File > Preferences > Settings > ClassiCode`:

```json
{
  "fileClassification.labels": ["Public", "Internal", "Confidential", "Personal"],
  "fileClassification.colors": {
    "Public": "#28a745",
    "Internal": "#ffc107", 
    "Confidential": "#dc3545",
    "Personal": "#6f42c1"
  },
  "fileClassification.enforceClassification": true,
  "fileClassification.enableWatermarks": true,
  "fileClassification.watermarkIntensity": "medium",
  "fileClassification.excludePatterns": ["**/node_modules/**", "**/.git/**"]
}
```

## 🎯 Commands

| Command | Description | Shortcut |
|---------|-------------|----------|
| **Classify File** | Assign permanent classification to file | Right-click context |
| **Show Classification Data** | Debug view of file metadata | Right-click context |
| **Verify Integrity** | Check for tampering or corruption | Right-click context |
| **Copy (Protected)** | Classification-aware copy operation | `Ctrl+C` / `Cmd+C` |
| **Cut (Protected)** | Classification-aware cut operation | `Ctrl+X` / `Cmd+X` |

## 🏢 Enterprise Features

### **DSPM Compliance**
- Machine-readable metadata format
- Integration with security posture management tools
- Compliance reporting and audit trails

### **Advanced Security**
- Cryptographic integrity verification
- Multi-location backup storage
- Tamper detection and automatic restoration
- File immutability flags for critical assets

### **Team Collaboration**
- Consistent classification across team members
- Centralized policy management
- Role-based access controls (coming soon)

## 📋 Requirements

- **VS Code**: 1.74.0 or higher
- **Operating System**: macOS, Windows, Linux
- **Node.js**: 16.x or higher (for development)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 🐛 Issues & Support

- **Bug Reports**: [GitHub Issues](https://github.com/27dikshant/classicode/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/27dikshant/classicode/discussions)
- **Email Support**: 27dikshant@gmail.com

## 🔗 Links

- **VS Code Marketplace**: [ClassiCode Extension](https://marketplace.visualstudio.com/items?itemName=dikshant.classicode)
- **GitHub Repository**: [27dikshant/classicode](https://github.com/27dikshant/classicode)
- **Author LinkedIn**: [Dikshant](https://www.linkedin.com/in/profile-dikshant/)

---

**Made with ❤️ for secure development workflows**

*ClassiCode helps teams maintain code security without compromising productivity.*

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.