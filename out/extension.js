"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const child_process_1 = require("child_process");
const util_1 = require("util");
const execAsync = (0, util_1.promisify)(child_process_1.exec);
var ClassificationLevel;
(function (ClassificationLevel) {
    ClassificationLevel["PUBLIC"] = "public";
    ClassificationLevel["INTERNAL"] = "internal";
    ClassificationLevel["CONFIDENTIAL"] = "confidential";
    ClassificationLevel["PERSONAL"] = "personal";
})(ClassificationLevel || (ClassificationLevel = {}));
var DLPAction;
(function (DLPAction) {
    DLPAction["COPY"] = "copy";
    DLPAction["CUT"] = "cut";
    DLPAction["PASTE"] = "paste";
    DLPAction["DUPLICATE"] = "duplicate";
    DLPAction["SAVE_AS"] = "save_as";
    DLPAction["RENAME"] = "rename";
    DLPAction["DELETE"] = "delete";
    DLPAction["EXTERNAL_UPLOAD"] = "external_upload";
})(DLPAction || (DLPAction = {}));
// ============================================================================
// FILE ATTRIBUTE MANAGER
// ============================================================================
class FileAttributeManager {
    static async setClassification(filePath, classification) {
        try {
            const timestamp = Date.now().toString();
            const verificationHash = crypto.createHash('sha256')
                .update(filePath + classification + timestamp + 'SECRET_SALT_2024')
                .digest('hex');
            // Set basic classification attributes
            await execAsync(`xattr -w "${this.CLASSIFICATION_ATTR}" "${classification}" "${filePath}"`);
            await execAsync(`xattr -w "${this.TIMESTAMP_ATTR}" "${timestamp}" "${filePath}"`);
            await execAsync(`xattr -w "${this.VERIFICATION_ATTR}" "${verificationHash}" "${filePath}"`);
            // Set DSPM watermark metadata
            await this.setDSPMWatermarkMetadata(filePath, classification, timestamp);
            // Create backup files
            await this.createBackupClassification(filePath, classification, timestamp, verificationHash);
            this.invalidateCache(filePath);
            console.log(`Classification set: ${classification} for ${path.basename(filePath)}`);
        }
        catch (error) {
            console.error('Failed to set file classification:', error);
            throw new Error('Failed to set permanent file classification');
        }
    }
    static async getClassification(filePath) {
        try {
            const cacheKey = `${filePath}:classification`;
            const cached = this.xattrCache.get(cacheKey);
            const now = Date.now();
            if (cached && (now - cached.timestamp) < this.XATTR_CACHE_DURATION) {
                return cached.value;
            }
            const result = await execAsync(`xattr -p "${this.CLASSIFICATION_ATTR}" "${filePath}"`);
            const classification = result.stdout.trim();
            this.xattrCache.set(cacheKey, { value: classification, timestamp: now });
            return classification;
        }
        catch (error) {
            this.xattrCache.set(`${filePath}:classification`, { value: null, timestamp: Date.now() });
            return null;
        }
    }
    static async setDSPMWatermarkMetadata(filePath, classification, timestamp) {
        try {
            const watermarkContent = `WATERMARKED:${classification}:${timestamp}:${path.basename(filePath)}`;
            const watermarkHash = crypto.createHash('sha256').update(watermarkContent + 'DSPM_SECRET_2024').digest('hex');
            const policyId = this.getDSPMPolicyId(classification);
            const leakProtectionLevel = this.getLeakProtectionLevel(classification);
            await execAsync(`xattr -w "${this.WATERMARK_STATUS_ATTR}" "ACTIVE" "${filePath}"`);
            await execAsync(`xattr -w "${this.WATERMARK_HASH_ATTR}" "${watermarkHash}" "${filePath}"`);
            await execAsync(`xattr -w "${this.DSPM_POLICY_ATTR}" "${policyId}" "${filePath}"`);
            await execAsync(`xattr -w "${this.LEAK_PROTECTION_ATTR}" "${leakProtectionLevel}" "${filePath}"`);
        }
        catch (error) {
            console.warn('Failed to set DSPM watermark metadata:', error);
        }
    }
    static async createBackupClassification(filePath, classification, timestamp, verificationHash) {
        try {
            const backupData = {
                originalFile: filePath,
                classification,
                timestamp,
                verificationHash,
                createdAt: new Date().toISOString()
            };
            const backupLocations = [
                path.join(path.dirname(filePath), `.${path.basename(filePath)}.classification`),
                path.join(require('os').tmpdir(), `cls_${crypto.createHash('md5').update(filePath).digest('hex')}.bak`),
                path.join(require('os').homedir(), '.file-classifications', crypto.createHash('md5').update(filePath).digest('hex'))
            ];
            const homeBackupDir = path.join(require('os').homedir(), '.file-classifications');
            if (!fs.existsSync(homeBackupDir)) {
                fs.mkdirSync(homeBackupDir, { recursive: true });
            }
            for (const backupPath of backupLocations) {
                try {
                    fs.writeFileSync(backupPath, JSON.stringify(backupData, null, 2));
                }
                catch (writeError) {
                    console.warn(`Could not create backup at ${backupPath}:`, writeError);
                }
            }
        }
        catch (error) {
            console.warn('Could not create backup classification:', error);
        }
    }
    static getDSPMPolicyId(classification) {
        switch (classification.toLowerCase()) {
            case 'confidential': return 'POLICY_CONF_001';
            case 'personal': return 'POLICY_PERS_001';
            case 'internal': return 'POLICY_INT_001';
            default: return 'POLICY_PUB_001';
        }
    }
    static getLeakProtectionLevel(classification) {
        switch (classification.toLowerCase()) {
            case 'confidential': return 'MAXIMUM';
            case 'personal': return 'HIGH';
            case 'internal': return 'MEDIUM';
            default: return 'LOW';
        }
    }
    static invalidateCache(filePath) {
        const cacheKey = `${filePath}:classification`;
        this.xattrCache.delete(cacheKey);
    }
}
FileAttributeManager.CLASSIFICATION_ATTR = 'user.file-classification';
FileAttributeManager.TIMESTAMP_ATTR = 'user.file-classification-timestamp';
FileAttributeManager.VERIFICATION_ATTR = 'user.file-classification-verify';
FileAttributeManager.WATERMARK_STATUS_ATTR = 'user.dspm-watermark-status';
FileAttributeManager.WATERMARK_HASH_ATTR = 'user.dspm-watermark-hash';
FileAttributeManager.DSPM_POLICY_ATTR = 'user.dspm-policy-id';
FileAttributeManager.LEAK_PROTECTION_ATTR = 'user.dspm-leak-protection';
FileAttributeManager.xattrCache = new Map();
FileAttributeManager.XATTR_CACHE_DURATION = 60000; // 1 minute
// ============================================================================
// DLP POLICY MANAGER
// ============================================================================
class DLPPolicyManager {
    static evaluateAction(classification, action) {
        // Unclassified files have no restrictions
        if (!classification) {
            return { allowed: true, level: 'allow' };
        }
        const level = classification.toLowerCase();
        switch (level) {
            case ClassificationLevel.PUBLIC:
                return { allowed: true, level: 'allow' };
            case ClassificationLevel.INTERNAL:
                return this.evaluateInternalPolicy(action);
            case ClassificationLevel.PERSONAL:
                return this.evaluatePersonalPolicy(action);
            case ClassificationLevel.CONFIDENTIAL:
                return this.evaluateConfidentialPolicy(action);
            default:
                return { allowed: true, level: 'allow' };
        }
    }
    static evaluateInternalPolicy(action) {
        switch (action) {
            case DLPAction.EXTERNAL_UPLOAD:
                return {
                    allowed: false,
                    requiresConfirmation: true,
                    message: 'Internal files require confirmation before external upload. Proceed with caution.',
                    level: 'warn'
                };
            default:
                return { allowed: true, level: 'allow' };
        }
    }
    static evaluatePersonalPolicy(action) {
        switch (action) {
            case DLPAction.EXTERNAL_UPLOAD:
                return {
                    allowed: false,
                    requiresConfirmation: true,
                    message: 'Personal files require confirmation before external upload/sharing.',
                    level: 'warn'
                };
            default:
                return { allowed: true, level: 'allow' };
        }
    }
    static evaluateConfidentialPolicy(action) {
        switch (action) {
            case DLPAction.COPY:
            case DLPAction.CUT:
            case DLPAction.DUPLICATE:
            case DLPAction.SAVE_AS:
            case DLPAction.RENAME:
            case DLPAction.EXTERNAL_UPLOAD:
                return {
                    allowed: false,
                    message: `${action} is disabled for confidential files to prevent data leakage.`,
                    level: 'block'
                };
            case DLPAction.PASTE:
            case DLPAction.DELETE:
                return { allowed: true, level: 'allow' };
            default:
                return { allowed: false, message: 'Action not permitted for confidential files.', level: 'block' };
        }
    }
    static async getCurrentFileClassification() {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor || activeEditor.document.uri.scheme !== 'file') {
            return null;
        }
        return await FileAttributeManager.getClassification(activeEditor.document.uri.fsPath);
    }
    static showActionResult(result, classification, action) {
        if (result.level === 'block') {
            vscode.window.showErrorMessage(`🔒 BLOCKED: ${result.message} (File: ${classification})`);
        }
        else if (result.level === 'warn') {
            vscode.window.showWarningMessage(`⚠️ WARNING: ${result.message} (File: ${classification})`);
        }
    }
}
// ============================================================================
// CLIPBOARD PROTECTION (CONFIDENTIAL ONLY)
// ============================================================================
class ClipboardProtector {
    static startMonitoring() {
        if (this.isActive) {
            return;
        }
        this.isActive = true;
        this.monitoringInterval = setInterval(async () => {
            await this.checkAndClearClipboard();
        }, 1000);
        console.log('Clipboard monitoring started for confidential content');
    }
    static stopMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }
        this.isActive = false;
        this.confidentialContent.clear();
        console.log('Clipboard monitoring stopped');
    }
    static trackConfidentialContent(content) {
        if (content.trim().length > 10) { // Only track substantial content
            this.confidentialContent.add(content.trim());
            // Keep only recent entries to prevent memory bloat
            if (this.confidentialContent.size > 50) {
                const first = this.confidentialContent.values().next().value;
                this.confidentialContent.delete(first);
            }
        }
    }
    static async checkAndClearClipboard() {
        try {
            const clipboardText = await vscode.env.clipboard.readText();
            if (!clipboardText) {
                return;
            }
            // Check if clipboard contains any confidential content
            for (const confidentialText of this.confidentialContent) {
                if (clipboardText.includes(confidentialText) || confidentialText.includes(clipboardText)) {
                    await vscode.env.clipboard.writeText('');
                    vscode.window.showErrorMessage('🔒 Clipboard cleared: Confidential content detected and removed');
                    this.confidentialContent.delete(confidentialText);
                    break;
                }
            }
        }
        catch (error) {
            // Ignore clipboard access errors
        }
    }
}
ClipboardProtector.isActive = false;
ClipboardProtector.monitoringInterval = null;
ClipboardProtector.confidentialContent = new Set();
// ============================================================================
// FILE OPERATION MONITOR (CONFIDENTIAL ONLY)
// ============================================================================
class FileOperationMonitor {
    static startMonitoring() {
        if (this.fileWatcher) {
            return;
        }
        this.fileWatcher = vscode.workspace.createFileSystemWatcher('**/*');
        this.fileWatcher.onDidCreate(async (uri) => {
            await this.handleFileCreation(uri);
        });
        console.log('File operation monitoring started for confidential files');
    }
    static stopMonitoring() {
        if (this.fileWatcher) {
            this.fileWatcher.dispose();
            this.fileWatcher = null;
        }
        console.log('File operation monitoring stopped');
    }
    static async handleFileCreation(uri) {
        try {
            // Check if this is a duplicate of a confidential file
            const originalFile = await this.findOriginalConfidentialFile(uri.fsPath);
            if (originalFile) {
                // Delete the duplicate
                setTimeout(async () => {
                    try {
                        await vscode.workspace.fs.delete(uri);
                        vscode.window.showErrorMessage(`🔒 File duplication blocked: Cannot duplicate confidential files`);
                    }
                    catch (error) {
                        vscode.window.showWarningMessage(`⚠️ Detected unauthorized duplication of confidential file`);
                    }
                }, 500);
            }
        }
        catch (error) {
            console.error('Error handling file creation:', error);
        }
    }
    static async findOriginalConfidentialFile(newFilePath) {
        const dir = path.dirname(newFilePath);
        const basename = path.basename(newFilePath);
        try {
            const files = await vscode.workspace.fs.readDirectory(vscode.Uri.file(dir));
            for (const [fileName, fileType] of files) {
                if (fileType === vscode.FileType.File && fileName !== basename) {
                    const filePath = path.join(dir, fileName);
                    const classification = await FileAttributeManager.getClassification(filePath);
                    if (classification && classification.toLowerCase() === 'confidential') {
                        // Check for copy patterns
                        if (this.isDuplicatePattern(basename, fileName)) {
                            return filePath;
                        }
                    }
                }
            }
        }
        catch (error) {
            // Ignore directory read errors
        }
        return null;
    }
    static isDuplicatePattern(newName, originalName) {
        // Check for common duplicate patterns
        const patterns = [
            /\s+copy/i,
            /\s*\(\d+\)/,
            /_copy/i,
            /-copy/i
        ];
        const originalBase = originalName.replace(/\.[^.]*$/, '');
        const newBase = newName.replace(/\.[^.]*$/, '');
        return patterns.some(pattern => {
            const cleaned = newBase.replace(pattern, '');
            return cleaned === originalBase;
        });
    }
}
FileOperationMonitor.fileWatcher = null;
// ============================================================================
// WATERMARK SYSTEM
// ============================================================================
class WatermarkManager {
    constructor() {
        this.initializeWatermarkDecorations();
    }
    initializeWatermarkDecorations() {
        this.confidentialDecorationType = vscode.window.createTextEditorDecorationType({
            after: {
                contentText: '🔒 CONFIDENTIAL',
                color: '#ff4444',
                fontWeight: 'bold',
                margin: '0 0 0 20px'
            },
            isWholeLine: true
        });
        this.personalDecorationType = vscode.window.createTextEditorDecorationType({
            after: {
                contentText: '👤 PERSONAL',
                color: '#9966ff',
                fontWeight: 'bold',
                margin: '0 0 0 20px'
            },
            isWholeLine: true
        });
        this.internalDecorationType = vscode.window.createTextEditorDecorationType({
            after: {
                contentText: '🏢 INTERNAL',
                color: '#ffaa00',
                fontWeight: 'bold',
                margin: '0 0 0 20px'
            },
            isWholeLine: true
        });
    }
    async applyWatermarks(editor) {
        const filePath = editor.document.uri.fsPath;
        const classification = await FileAttributeManager.getClassification(filePath);
        if (!classification) {
            return;
        }
        const config = vscode.workspace.getConfiguration('fileClassification');
        const watermarksEnabled = config.get('enableWatermarks', true);
        const intensity = config.get('watermarkIntensity', 'medium');
        // Confidential files MUST always show watermarks
        if (!watermarksEnabled && classification.toLowerCase() !== 'confidential') {
            return;
        }
        this.clearWatermarks(editor);
        const decorationType = this.getDecorationTypeForClassification(classification);
        if (!decorationType) {
            return;
        }
        const ranges = [];
        const lineCount = editor.document.lineCount;
        const watermarkPositions = this.calculateWatermarkPositions(lineCount, intensity, classification);
        for (const lineNum of watermarkPositions) {
            if (lineNum < lineCount) {
                const line = editor.document.lineAt(lineNum);
                ranges.push(new vscode.Range(lineNum, line.text.length, lineNum, line.text.length));
            }
        }
        editor.setDecorations(decorationType, ranges);
    }
    calculateWatermarkPositions(lineCount, intensity, classification) {
        const positions = [];
        positions.push(0, Math.floor(lineCount / 4), Math.floor(lineCount / 2), Math.floor(lineCount * 3 / 4), Math.max(0, lineCount - 1));
        let interval;
        switch (intensity) {
            case 'light':
                interval = 25;
                break;
            case 'heavy':
                interval = 8;
                break;
            default:
                interval = 15;
                break;
        }
        if (classification.toLowerCase() === 'confidential') {
            interval = Math.min(interval, 10);
        }
        for (let i = interval; i < lineCount; i += interval) {
            positions.push(i);
        }
        return [...new Set(positions)].sort((a, b) => a - b);
    }
    getDecorationTypeForClassification(classification) {
        switch (classification.toLowerCase()) {
            case 'confidential': return this.confidentialDecorationType;
            case 'personal': return this.personalDecorationType;
            case 'internal': return this.internalDecorationType;
            default: return null;
        }
    }
    clearWatermarks(editor) {
        editor.setDecorations(this.confidentialDecorationType, []);
        editor.setDecorations(this.personalDecorationType, []);
        editor.setDecorations(this.internalDecorationType, []);
    }
    async refreshAllWatermarks() {
        for (const editor of vscode.window.visibleTextEditors) {
            if (editor.document.uri.scheme === 'file') {
                await this.applyWatermarks(editor);
            }
        }
    }
}
// ============================================================================
// FILE CLASSIFICATION PROVIDER
// ============================================================================
class FileClassificationProvider {
    constructor() {
        this._onDidChangeFileDecorations = new vscode.EventEmitter();
        this.onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;
        this.classificationData = {};
        this.watermarkManager = new WatermarkManager();
        this.loadClassificationData();
    }
    async provideFileDecoration(uri) {
        const classification = await FileAttributeManager.getClassification(uri.fsPath);
        if (!classification) {
            return undefined;
        }
        const config = vscode.workspace.getConfiguration('fileClassification');
        const colors = config.get('colors') || {};
        const color = colors[classification] || '#666666';
        return {
            badge: classification.charAt(0).toUpperCase(),
            tooltip: `Classification: ${classification} (PERMANENT)`,
            color: new vscode.ThemeColor('fileClassification.badge'),
            propagate: false
        };
    }
    refresh(uri) {
        this.loadClassificationData();
        this._onDidChangeFileDecorations.fire(uri);
        this.watermarkManager.refreshAllWatermarks();
    }
    async setFileClassification(filePath, classification) {
        const existingClassification = await FileAttributeManager.getClassification(filePath);
        if (existingClassification) {
            throw new Error('File classification is permanent and cannot be changed');
        }
        await FileAttributeManager.setClassification(filePath, classification);
        this.classificationData[filePath] = {
            classification,
            timestamp: Date.now(),
            hash: 'n/a',
            locked: true
        };
        this.saveClassificationData();
        this.refresh(vscode.Uri.file(filePath));
    }
    loadClassificationData() {
        if (!vscode.workspace.workspaceFolders) {
            return;
        }
        const workspaceRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
        const classificationFile = path.join(workspaceRoot, '.classification.json');
        try {
            if (fs.existsSync(classificationFile)) {
                const data = fs.readFileSync(classificationFile, 'utf8');
                this.classificationData = JSON.parse(data);
            }
        }
        catch (error) {
            console.error('Failed to load classification data:', error);
        }
    }
    saveClassificationData() {
        if (!vscode.workspace.workspaceFolders) {
            return;
        }
        const workspaceRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
        const classificationFile = path.join(workspaceRoot, '.classification.json');
        try {
            fs.writeFileSync(classificationFile, JSON.stringify(this.classificationData, null, 2));
        }
        catch (error) {
            console.error('Failed to save classification data:', error);
        }
    }
    getWatermarkManager() {
        return this.watermarkManager;
    }
}
// ============================================================================
// COMMAND HANDLERS
// ============================================================================
class CommandHandler {
    static async handleCopy() {
        const classification = await DLPPolicyManager.getCurrentFileClassification();
        const result = DLPPolicyManager.evaluateAction(classification, DLPAction.COPY);
        if (!result.allowed) {
            DLPPolicyManager.showActionResult(result, classification || 'Unknown', 'copy');
            return;
        }
        // Execute original copy
        await vscode.commands.executeCommand('editor.action.clipboardCopyAction');
        // Track confidential content for clipboard monitoring
        if (classification && classification.toLowerCase() === 'confidential') {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor && !activeEditor.selection.isEmpty) {
                const selectedText = activeEditor.document.getText(activeEditor.selection);
                ClipboardProtector.trackConfidentialContent(selectedText);
            }
        }
        // Show warning for internal/personal
        if (classification && ['internal', 'personal'].includes(classification.toLowerCase())) {
            vscode.window.showInformationMessage(`ℹ️ Copied content from ${classification} file - be cautious when pasting externally`);
        }
    }
    static async handleCut() {
        const classification = await DLPPolicyManager.getCurrentFileClassification();
        const result = DLPPolicyManager.evaluateAction(classification, DLPAction.CUT);
        if (!result.allowed) {
            DLPPolicyManager.showActionResult(result, classification || 'Unknown', 'cut');
            return;
        }
        await vscode.commands.executeCommand('editor.action.clipboardCutAction');
        if (classification && classification.toLowerCase() === 'confidential') {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor && !activeEditor.selection.isEmpty) {
                const selectedText = activeEditor.document.getText(activeEditor.selection);
                ClipboardProtector.trackConfidentialContent(selectedText);
            }
        }
        if (classification && ['internal', 'personal'].includes(classification.toLowerCase())) {
            vscode.window.showInformationMessage(`ℹ️ Cut content from ${classification} file - be cautious when pasting externally`);
        }
    }
    static async handleSaveAs() {
        const classification = await DLPPolicyManager.getCurrentFileClassification();
        const result = DLPPolicyManager.evaluateAction(classification, DLPAction.SAVE_AS);
        if (!result.allowed) {
            DLPPolicyManager.showActionResult(result, classification || 'Unknown', 'Save As');
            return;
        }
        await vscode.commands.executeCommand('workbench.action.files.saveAs');
    }
    static async handleDuplicate(uri) {
        if (!uri || uri.scheme !== 'file') {
            return;
        }
        const classification = await FileAttributeManager.getClassification(uri.fsPath);
        const result = DLPPolicyManager.evaluateAction(classification, DLPAction.DUPLICATE);
        if (!result.allowed) {
            DLPPolicyManager.showActionResult(result, classification || 'Unknown', 'duplicate');
            return;
        }
        await vscode.commands.executeCommand('filesExplorer.duplicateFile', uri);
    }
    static async handleRename(uri) {
        if (!uri || uri.scheme !== 'file') {
            return;
        }
        const classification = await FileAttributeManager.getClassification(uri.fsPath);
        const result = DLPPolicyManager.evaluateAction(classification, DLPAction.RENAME);
        if (!result.allowed) {
            DLPPolicyManager.showActionResult(result, classification || 'Unknown', 'rename');
            return;
        }
        await vscode.commands.executeCommand('filesExplorer.renameFile', uri);
    }
}
// ============================================================================
// MAIN EXTENSION
// ============================================================================
let fileDecorationProvider;
let hasConfidentialFiles = false;
function activate(context) {
    fileDecorationProvider = new FileClassificationProvider();
    const decorationDisposable = vscode.window.registerFileDecorationProvider(fileDecorationProvider);
    context.subscriptions.push(decorationDisposable);
    // Register commands
    registerCommands(context);
    // Setup monitoring systems
    setupMonitoringSystems(context);
    // Setup watermarks
    setupWatermarkSystem(context);
    console.log('File Classification extension activated with DLP protection');
}
exports.activate = activate;
function registerCommands(context) {
    // Classification commands
    const classifyCommand = vscode.commands.registerCommand('fileClassification.classifyFile', async (uri) => {
        if (uri && uri.scheme === 'file') {
            const document = await vscode.workspace.openTextDocument(uri);
            await classifyFile(document, true);
        }
    });
    // DLP intercepted commands
    const interceptedCopyCommand = vscode.commands.registerCommand('fileClassification.interceptedCopy', CommandHandler.handleCopy);
    const interceptedCutCommand = vscode.commands.registerCommand('fileClassification.interceptedCut', CommandHandler.handleCut);
    const interceptedSaveAsCommand = vscode.commands.registerCommand('fileClassification.interceptedSaveAs', CommandHandler.handleSaveAs);
    const interceptedDuplicateCommand = vscode.commands.registerCommand('fileClassification.interceptedDuplicate', CommandHandler.handleDuplicate);
    const interceptedRenameCommand = vscode.commands.registerCommand('fileClassification.interceptedRename', CommandHandler.handleRename);
    // Debug commands
    const showDataCommand = vscode.commands.registerCommand('fileClassification.showClassificationData', async (uri) => {
        if (uri && uri.scheme === 'file') {
            const classification = await FileAttributeManager.getClassification(uri.fsPath);
            const data = {
                filePath: uri.fsPath,
                classification: classification || 'Not classified',
                isClassified: classification !== null,
                instructions: 'To inspect from terminal, use: xattr -l "' + uri.fsPath + '"'
            };
            const doc = await vscode.workspace.openTextDocument({
                content: JSON.stringify(data, null, 2),
                language: 'json'
            });
            await vscode.window.showTextDocument(doc);
        }
    });
    context.subscriptions.push(classifyCommand, interceptedCopyCommand, interceptedCutCommand, interceptedSaveAsCommand, interceptedDuplicateCommand, interceptedRenameCommand, showDataCommand);
}
function setupMonitoringSystems(context) {
    // Monitor for confidential files and start/stop protection accordingly
    const documentWatcher = vscode.workspace.onDidOpenTextDocument(async (document) => {
        if (document.uri.scheme === 'file') {
            await updateProtectionSystems();
        }
    });
    const editorWatcher = vscode.window.onDidChangeActiveTextEditor(async () => {
        await updateProtectionSystems();
    });
    // Save event handler
    const saveDisposable = vscode.workspace.onWillSaveTextDocument(async (event) => {
        const document = event.document;
        if (document.uri.scheme !== 'file' || isExcludedFile(document.uri.fsPath)) {
            return;
        }
        if (isBinaryFile(document)) {
            return;
        }
        const isClassified = await FileAttributeManager.getClassification(document.uri.fsPath);
        if (isClassified) {
            return;
        }
        const config = vscode.workspace.getConfiguration('fileClassification');
        const enforceClassification = config.get('enforceClassification', true);
        if (enforceClassification) {
            event.waitUntil(classifyFile(document));
        }
    });
    context.subscriptions.push(documentWatcher, editorWatcher, saveDisposable);
}
async function updateProtectionSystems() {
    // Check if any open files are confidential
    let foundConfidential = false;
    for (const document of vscode.workspace.textDocuments) {
        if (document.uri.scheme === 'file') {
            const classification = await FileAttributeManager.getClassification(document.uri.fsPath);
            if (classification && classification.toLowerCase() === 'confidential') {
                foundConfidential = true;
                break;
            }
        }
    }
    // Start/stop protection systems based on confidential file presence
    if (foundConfidential && !hasConfidentialFiles) {
        hasConfidentialFiles = true;
        ClipboardProtector.startMonitoring();
        FileOperationMonitor.startMonitoring();
        console.log('Enhanced protection activated for confidential files');
    }
    else if (!foundConfidential && hasConfidentialFiles) {
        hasConfidentialFiles = false;
        ClipboardProtector.stopMonitoring();
        FileOperationMonitor.stopMonitoring();
        console.log('Enhanced protection deactivated - no confidential files open');
    }
}
function setupWatermarkSystem(context) {
    const activeEditorWatcher = vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (editor && editor.document.uri.scheme === 'file') {
            await fileDecorationProvider.getWatermarkManager().applyWatermarks(editor);
        }
    });
    const visibleEditorsWatcher = vscode.window.onDidChangeVisibleTextEditors(async (editors) => {
        for (const editor of editors) {
            if (editor.document.uri.scheme === 'file') {
                await fileDecorationProvider.getWatermarkManager().applyWatermarks(editor);
            }
        }
    });
    setTimeout(async () => {
        await fileDecorationProvider.getWatermarkManager().refreshAllWatermarks();
    }, 100);
    context.subscriptions.push(activeEditorWatcher, visibleEditorsWatcher);
}
async function classifyFile(document, force = false) {
    try {
        if (document.isUntitled) {
            return;
        }
        const isAlreadyClassified = await FileAttributeManager.getClassification(document.uri.fsPath);
        if (isAlreadyClassified) {
            const existingClassification = await FileAttributeManager.getClassification(document.uri.fsPath);
            vscode.window.showWarningMessage(`File is already permanently classified as: ${existingClassification}. Cannot be changed.`);
            return;
        }
        const config = vscode.workspace.getConfiguration('fileClassification');
        const labels = config.get('labels') || ['Public', 'Internal', 'Confidential', 'Personal'];
        const classification = await vscode.window.showQuickPick(labels, {
            placeHolder: 'Select file classification (PERMANENT - cannot be changed)',
            canPickMany: false,
            ignoreFocusOut: true
        });
        if (!classification) {
            vscode.window.showErrorMessage('File classification is mandatory. File cannot be saved without classification.');
            throw new Error('Classification is required before saving');
        }
        await fileDecorationProvider.setFileClassification(document.uri.fsPath, classification);
        const addVisualComment = config.get('addVisualComment', true);
        if (addVisualComment) {
            await insertClassificationComment(document, classification);
        }
        FileAttributeManager.invalidateCache(document.uri.fsPath);
        vscode.window.showInformationMessage(`File permanently classified as: ${classification}. Stored in file metadata - cannot be changed or removed.`);
        // Update protection systems
        await updateProtectionSystems();
    }
    catch (error) {
        if (error instanceof Error && error.message.includes('permanent')) {
            vscode.window.showErrorMessage(error.message);
        }
        else {
            vscode.window.showErrorMessage(`Classification failed: ${error}`);
        }
        throw error;
    }
}
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
const COMMENT_STYLES = {
    javascript: { prefix: '// ' },
    typescript: { prefix: '// ' },
    python: { prefix: '# ' },
    java: { prefix: '// ' },
    csharp: { prefix: '// ' },
    cpp: { prefix: '// ' },
    c: { prefix: '// ' },
    html: { prefix: '<!-- ', suffix: ' -->' },
    xml: { prefix: '<!-- ', suffix: ' -->' },
    css: { prefix: '/* ', suffix: ' */' },
    scss: { prefix: '// ' },
    less: { prefix: '// ' },
    php: { prefix: '// ' },
    ruby: { prefix: '# ' },
    go: { prefix: '// ' },
    rust: { prefix: '// ' },
    shell: { prefix: '# ' },
    powershell: { prefix: '# ' },
    yaml: { prefix: '# ' },
    json: { prefix: '// ' },
    sql: { prefix: '-- ' },
    r: { prefix: '# ' },
    matlab: { prefix: '% ' },
    tex: { prefix: '% ' }
};
async function insertClassificationComment(document, classification) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== document) {
        return;
    }
    const languageId = document.languageId;
    const commentStyle = getCommentStyle(languageId);
    if (!commentStyle) {
        return;
    }
    const classificationText = `Classification: ${classification}`;
    const commentLine = commentStyle.suffix
        ? `${commentStyle.prefix}${classificationText}${commentStyle.suffix}`
        : `${commentStyle.prefix}${classificationText}`;
    const firstLine = document.lineAt(0);
    const classificationRegex = new RegExp(`${escapeRegExp(commentStyle.prefix)}.*Classification:\\s*\\w+`);
    if (classificationRegex.test(firstLine.text)) {
        await editor.edit(editBuilder => {
            editBuilder.replace(new vscode.Range(0, 0, 0, firstLine.text.length), commentLine);
        });
    }
    else {
        await editor.edit(editBuilder => {
            editBuilder.insert(new vscode.Position(0, 0), commentLine + '\n');
        });
    }
}
function getCommentStyle(languageId) {
    return COMMENT_STYLES[languageId] || COMMENT_STYLES['javascript'];
}
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function isExcludedFile(filePath) {
    const config = vscode.workspace.getConfiguration('fileClassification');
    const excludePatterns = config.get('excludePatterns') || [];
    return excludePatterns.some(pattern => {
        const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
        return regex.test(filePath);
    });
}
function isBinaryFile(document) {
    const binaryExtensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.mp3', '.mp4', '.avi', '.mov', '.wav'];
    const ext = path.extname(document.fileName).toLowerCase();
    if (binaryExtensions.includes(ext)) {
        return true;
    }
    const text = document.getText(new vscode.Range(0, 0, Math.min(document.lineCount, 10), 0));
    return text.includes('\0');
}
function deactivate() {
    ClipboardProtector.stopMonitoring();
    FileOperationMonitor.stopMonitoring();
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map