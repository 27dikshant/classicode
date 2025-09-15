import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// ============================================================================
// INTERFACES AND TYPES
// ============================================================================

interface ClassificationData {
	[filePath: string]: {
		classification: string;
		timestamp: number;
		hash: string;
		locked: boolean;
	};
}

interface CommentStyle {
	prefix: string;
	suffix?: string;
}

enum ClassificationLevel {
	PUBLIC = 'public',
	INTERNAL = 'internal',
	CONFIDENTIAL = 'confidential',
	PERSONAL = 'personal'
}

enum DLPAction {
	COPY = 'copy',
	CUT = 'cut',
	PASTE = 'paste',
	DUPLICATE = 'duplicate',
	SAVE_AS = 'save_as',
	RENAME = 'rename',
	DELETE = 'delete',
	EXTERNAL_UPLOAD = 'external_upload'
}

interface DLPResult {
	allowed: boolean;
	requiresConfirmation?: boolean;
	message?: string;
	level: 'block' | 'warn' | 'allow';
}

// ============================================================================
// FILE ATTRIBUTE MANAGER
// ============================================================================

class FileAttributeManager {
	private static readonly CLASSIFICATION_ATTR = 'user.file-classification';
	private static readonly TIMESTAMP_ATTR = 'user.file-classification-timestamp';
	private static readonly VERIFICATION_ATTR = 'user.file-classification-verify';
	private static readonly WATERMARK_STATUS_ATTR = 'user.dspm-watermark-status';
	private static readonly WATERMARK_HASH_ATTR = 'user.dspm-watermark-hash';
	private static readonly DSPM_POLICY_ATTR = 'user.dspm-policy-id';
	private static readonly LEAK_PROTECTION_ATTR = 'user.dspm-leak-protection';

	private static xattrCache = new Map<string, { value: string | null, timestamp: number }>();
	private static XATTR_CACHE_DURATION = 60000; // 1 minute

	static async setClassification(filePath: string, classification: string): Promise<void> {
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
		} catch (error) {
			console.error('Failed to set file classification:', error);
			throw new Error('Failed to set permanent file classification');
		}
	}

	static async getClassification(filePath: string): Promise<string | null> {
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
		} catch (error) {
			this.xattrCache.set(`${filePath}:classification`, { value: null, timestamp: Date.now() });
			return null;
		}
	}

	private static async setDSPMWatermarkMetadata(filePath: string, classification: string, timestamp: string): Promise<void> {
		try {
			const watermarkContent = `WATERMARKED:${classification}:${timestamp}:${path.basename(filePath)}`;
			const watermarkHash = crypto.createHash('sha256').update(watermarkContent + 'DSPM_SECRET_2024').digest('hex');
			const policyId = this.getDSPMPolicyId(classification);
			const leakProtectionLevel = this.getLeakProtectionLevel(classification);

			await execAsync(`xattr -w "${this.WATERMARK_STATUS_ATTR}" "ACTIVE" "${filePath}"`);
			await execAsync(`xattr -w "${this.WATERMARK_HASH_ATTR}" "${watermarkHash}" "${filePath}"`);
			await execAsync(`xattr -w "${this.DSPM_POLICY_ATTR}" "${policyId}" "${filePath}"`);
			await execAsync(`xattr -w "${this.LEAK_PROTECTION_ATTR}" "${leakProtectionLevel}" "${filePath}"`);
		} catch (error) {
			console.warn('Failed to set DSPM watermark metadata:', error);
		}
	}

	private static async createBackupClassification(filePath: string, classification: string, timestamp: string, verificationHash: string): Promise<void> {
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
				} catch (writeError) {
					console.warn(`Could not create backup at ${backupPath}:`, writeError);
				}
			}
		} catch (error) {
			console.warn('Could not create backup classification:', error);
		}
	}

	private static getDSPMPolicyId(classification: string): string {
		switch (classification.toLowerCase()) {
			case 'confidential': return 'POLICY_CONF_001';
			case 'personal': return 'POLICY_PERS_001';
			case 'internal': return 'POLICY_INT_001';
			default: return 'POLICY_PUB_001';
		}
	}

	private static getLeakProtectionLevel(classification: string): string {
		switch (classification.toLowerCase()) {
			case 'confidential': return 'MAXIMUM';
			case 'personal': return 'HIGH';
			case 'internal': return 'MEDIUM';
			default: return 'LOW';
		}
	}

	static invalidateCache(filePath: string): void {
		const cacheKey = `${filePath}:classification`;
		this.xattrCache.delete(cacheKey);
	}
}

// ============================================================================
// DLP POLICY MANAGER
// ============================================================================

class DLPPolicyManager {
	static evaluateAction(classification: string | null, action: DLPAction): DLPResult {
		// Unclassified files have no restrictions
		if (!classification) {
			return { allowed: true, level: 'allow' };
		}

		const level = classification.toLowerCase() as ClassificationLevel;

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

	private static evaluateInternalPolicy(action: DLPAction): DLPResult {
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

	private static evaluatePersonalPolicy(action: DLPAction): DLPResult {
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

	private static evaluateConfidentialPolicy(action: DLPAction): DLPResult {
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

	static async getCurrentFileClassification(): Promise<string | null> {
		const activeEditor = vscode.window.activeTextEditor;
		if (!activeEditor || activeEditor.document.uri.scheme !== 'file') {
			return null;
		}
		return await FileAttributeManager.getClassification(activeEditor.document.uri.fsPath);
	}

	static showActionResult(result: DLPResult, classification: string, action: string): void {
		if (result.level === 'block') {
			vscode.window.showErrorMessage(`🔒 BLOCKED: ${result.message} (File: ${classification})`);
		} else if (result.level === 'warn') {
			vscode.window.showWarningMessage(`⚠️ WARNING: ${result.message} (File: ${classification})`);
		}
	}
}

// ============================================================================
// CLIPBOARD PROTECTION (CONFIDENTIAL ONLY)
// ============================================================================

class ClipboardProtector {
	private static isActive = false;
	private static monitoringInterval: NodeJS.Timeout | null = null;
	private static confidentialContent = new Set<string>();

	static startMonitoring(): void {
		if (this.isActive) {return;}

		this.isActive = true;
		this.monitoringInterval = setInterval(async () => {
			await this.checkAndClearClipboard();
		}, 1000);

		console.log('Clipboard monitoring started for confidential content');
	}

	static stopMonitoring(): void {
		if (this.monitoringInterval) {
			clearInterval(this.monitoringInterval);
			this.monitoringInterval = null;
		}
		this.isActive = false;
		this.confidentialContent.clear();
		console.log('Clipboard monitoring stopped');
	}

	static trackConfidentialContent(content: string): void {
		if (content.trim().length > 10) { // Only track substantial content
			this.confidentialContent.add(content.trim());
			// Keep only recent entries to prevent memory bloat
			if (this.confidentialContent.size > 50) {
				const first = this.confidentialContent.values().next().value;
				this.confidentialContent.delete(first);
			}
		}
	}

	private static async checkAndClearClipboard(): Promise<void> {
		try {
			const clipboardText = await vscode.env.clipboard.readText();
			if (!clipboardText) {return;}

			// Check if clipboard contains any confidential content
			for (const confidentialText of this.confidentialContent) {
				if (clipboardText.includes(confidentialText) || confidentialText.includes(clipboardText)) {
					await vscode.env.clipboard.writeText('');
					vscode.window.showErrorMessage('🔒 Clipboard cleared: Confidential content detected and removed');
					this.confidentialContent.delete(confidentialText);
					break;
				}
			}
		} catch (error) {
			// Ignore clipboard access errors
		}
	}
}

// ============================================================================
// FILE OPERATION MONITOR (CONFIDENTIAL ONLY)
// ============================================================================

class FileOperationMonitor {
	private static fileWatcher: vscode.FileSystemWatcher | null = null;

	static startMonitoring(): void {
		if (this.fileWatcher) {return;}

		this.fileWatcher = vscode.workspace.createFileSystemWatcher('**/*');
		
		this.fileWatcher.onDidCreate(async (uri) => {
			await this.handleFileCreation(uri);
		});

		console.log('File operation monitoring started for confidential files');
	}

	static stopMonitoring(): void {
		if (this.fileWatcher) {
			this.fileWatcher.dispose();
			this.fileWatcher = null;
		}
		console.log('File operation monitoring stopped');
	}

	private static async handleFileCreation(uri: vscode.Uri): Promise<void> {
		try {
			// Check if this is a duplicate of a confidential file
			const originalFile = await this.findOriginalConfidentialFile(uri.fsPath);
			if (originalFile) {
				// Delete the duplicate
				setTimeout(async () => {
					try {
						await vscode.workspace.fs.delete(uri);
						vscode.window.showErrorMessage(`🔒 File duplication blocked: Cannot duplicate confidential files`);
					} catch (error) {
						vscode.window.showWarningMessage(`⚠️ Detected unauthorized duplication of confidential file`);
					}
				}, 500);
			}
		} catch (error) {
			console.error('Error handling file creation:', error);
		}
	}

	private static async findOriginalConfidentialFile(newFilePath: string): Promise<string | null> {
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
		} catch (error) {
			// Ignore directory read errors
		}

		return null;
	}

	private static isDuplicatePattern(newName: string, originalName: string): boolean {
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

// ============================================================================
// WATERMARK SYSTEM
// ============================================================================

class WatermarkManager {
	private confidentialDecorationType!: vscode.TextEditorDecorationType;
	private personalDecorationType!: vscode.TextEditorDecorationType;
	private internalDecorationType!: vscode.TextEditorDecorationType;

	constructor() {
		this.initializeWatermarkDecorations();
	}

	private initializeWatermarkDecorations() {
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

	async applyWatermarks(editor: vscode.TextEditor): Promise<void> {
		const filePath = editor.document.uri.fsPath;
		const classification = await FileAttributeManager.getClassification(filePath);
		
		if (!classification) {
			return;
		}

		const config = vscode.workspace.getConfiguration('fileClassification');
		const watermarksEnabled = config.get<boolean>('enableWatermarks', true);
		const intensity = config.get<string>('watermarkIntensity', 'medium');
		
		// Confidential files MUST always show watermarks
		if (!watermarksEnabled && classification.toLowerCase() !== 'confidential') {
			return;
		}

		this.clearWatermarks(editor);

		const decorationType = this.getDecorationTypeForClassification(classification);
		if (!decorationType) {
			return;
		}

		const ranges: vscode.Range[] = [];
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

	private calculateWatermarkPositions(lineCount: number, intensity: string, classification: string): number[] {
		const positions: number[] = [];
		
		positions.push(
			0,
			Math.floor(lineCount / 4),
			Math.floor(lineCount / 2),
			Math.floor(lineCount * 3 / 4),
			Math.max(0, lineCount - 1)
		);

		let interval: number;
		switch (intensity) {
			case 'light': interval = 25; break;
			case 'heavy': interval = 8; break;
			default: interval = 15; break;
		}

		if (classification.toLowerCase() === 'confidential') {
			interval = Math.min(interval, 10);
		}

		for (let i = interval; i < lineCount; i += interval) {
			positions.push(i);
		}

		return [...new Set(positions)].sort((a, b) => a - b);
	}

	private getDecorationTypeForClassification(classification: string): vscode.TextEditorDecorationType | null {
		switch (classification.toLowerCase()) {
			case 'confidential': return this.confidentialDecorationType;
			case 'personal': return this.personalDecorationType;
			case 'internal': return this.internalDecorationType;
			default: return null;
		}
	}

	private clearWatermarks(editor: vscode.TextEditor): void {
		editor.setDecorations(this.confidentialDecorationType, []);
		editor.setDecorations(this.personalDecorationType, []);
		editor.setDecorations(this.internalDecorationType, []);
	}

	async refreshAllWatermarks(): Promise<void> {
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

class FileClassificationProvider implements vscode.FileDecorationProvider {
	private _onDidChangeFileDecorations: vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined> = 
		new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
	readonly onDidChangeFileDecorations: vscode.Event<vscode.Uri | vscode.Uri[] | undefined> = 
		this._onDidChangeFileDecorations.event;

	private classificationData: ClassificationData = {};
	private watermarkManager = new WatermarkManager();

	constructor() {
		this.loadClassificationData();
	}

	async provideFileDecoration(uri: vscode.Uri): Promise<vscode.FileDecoration | undefined> {
		const classification = await FileAttributeManager.getClassification(uri.fsPath);
		if (!classification) {
			return undefined;
		}

		const config = vscode.workspace.getConfiguration('fileClassification');
		const colors = config.get<Record<string, string>>('colors') || {};
		const color = colors[classification] || '#666666';

		return {
			badge: classification.charAt(0).toUpperCase(),
			tooltip: `Classification: ${classification} (PERMANENT)`,
			color: new vscode.ThemeColor('fileClassification.badge'),
			propagate: false
		};
	}

	refresh(uri?: vscode.Uri): void {
		this.loadClassificationData();
		this._onDidChangeFileDecorations.fire(uri);
		this.watermarkManager.refreshAllWatermarks();
	}

	async setFileClassification(filePath: string, classification: string): Promise<void> {
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

	private loadClassificationData(): void {
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
		} catch (error) {
			console.error('Failed to load classification data:', error);
		}
	}

	private saveClassificationData(): void {
		if (!vscode.workspace.workspaceFolders) {
			return;
		}

		const workspaceRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
		const classificationFile = path.join(workspaceRoot, '.classification.json');

		try {
			fs.writeFileSync(classificationFile, JSON.stringify(this.classificationData, null, 2));
		} catch (error) {
			console.error('Failed to save classification data:', error);
		}
	}

	getWatermarkManager(): WatermarkManager {
		return this.watermarkManager;
	}
}

// ============================================================================
// COMMAND HANDLERS
// ============================================================================

class CommandHandler {
	static async handleCopy(): Promise<void> {
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

	static async handleCut(): Promise<void> {
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

	static async handleSaveAs(): Promise<void> {
		const classification = await DLPPolicyManager.getCurrentFileClassification();
		const result = DLPPolicyManager.evaluateAction(classification, DLPAction.SAVE_AS);

		if (!result.allowed) {
			DLPPolicyManager.showActionResult(result, classification || 'Unknown', 'Save As');
			return;
		}

		await vscode.commands.executeCommand('workbench.action.files.saveAs');
	}

	static async handleDuplicate(uri?: vscode.Uri): Promise<void> {
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

	static async handleRename(uri?: vscode.Uri): Promise<void> {
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

let fileDecorationProvider: FileClassificationProvider;
let hasConfidentialFiles = false;

export function activate(context: vscode.ExtensionContext) {
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

function registerCommands(context: vscode.ExtensionContext) {
	// Classification commands
	const classifyCommand = vscode.commands.registerCommand('fileClassification.classifyFile', async (uri: vscode.Uri) => {
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
	const showDataCommand = vscode.commands.registerCommand('fileClassification.showClassificationData', async (uri?: vscode.Uri) => {
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

	context.subscriptions.push(
		classifyCommand,
		interceptedCopyCommand,
		interceptedCutCommand,
		interceptedSaveAsCommand,
		interceptedDuplicateCommand,
		interceptedRenameCommand,
		showDataCommand
	);
}

function setupMonitoringSystems(context: vscode.ExtensionContext) {
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
		const enforceClassification = config.get<boolean>('enforceClassification', true);
		
		if (enforceClassification) {
			event.waitUntil(classifyFile(document));
		}
	});

	context.subscriptions.push(documentWatcher, editorWatcher, saveDisposable);
}

async function updateProtectionSystems(): Promise<void> {
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
	} else if (!foundConfidential && hasConfidentialFiles) {
		hasConfidentialFiles = false;
		ClipboardProtector.stopMonitoring();
		FileOperationMonitor.stopMonitoring();
		console.log('Enhanced protection deactivated - no confidential files open');
	}
}

function setupWatermarkSystem(context: vscode.ExtensionContext) {
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

async function classifyFile(document: vscode.TextDocument, force: boolean = false): Promise<void> {
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
		const labels = config.get<string[]>('labels') || ['Public', 'Internal', 'Confidential', 'Personal'];

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

		const addVisualComment = config.get<boolean>('addVisualComment', true);
		if (addVisualComment) {
			await insertClassificationComment(document, classification);
		}

		FileAttributeManager.invalidateCache(document.uri.fsPath);

		vscode.window.showInformationMessage(`File permanently classified as: ${classification}. Stored in file metadata - cannot be changed or removed.`);

		// Update protection systems
		await updateProtectionSystems();

	} catch (error) {
		if (error instanceof Error && error.message.includes('permanent')) {
			vscode.window.showErrorMessage(error.message);
		} else {
			vscode.window.showErrorMessage(`Classification failed: ${error}`);
		}
		throw error;
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const COMMENT_STYLES: { [key: string]: CommentStyle } = {
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

async function insertClassificationComment(document: vscode.TextDocument, classification: string): Promise<void> {
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
			editBuilder.replace(
				new vscode.Range(0, 0, 0, firstLine.text.length),
				commentLine
			);
		});
	} else {
		await editor.edit(editBuilder => {
			editBuilder.insert(new vscode.Position(0, 0), commentLine + '\n');
		});
	}
}

function getCommentStyle(languageId: string): CommentStyle | undefined {
	return COMMENT_STYLES[languageId] || COMMENT_STYLES['javascript'];
}

function escapeRegExp(string: string): string {
	return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isExcludedFile(filePath: string): boolean {
	const config = vscode.workspace.getConfiguration('fileClassification');
	const excludePatterns = config.get<string[]>('excludePatterns') || [];
	
	return excludePatterns.some(pattern => {
		const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
		return regex.test(filePath);
	});
}

function isBinaryFile(document: vscode.TextDocument): boolean {
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

export function deactivate() {
	ClipboardProtector.stopMonitoring();
	FileOperationMonitor.stopMonitoring();
}