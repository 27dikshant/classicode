# Contributing to ClassiCode

Thank you for your interest in contributing to ClassiCode! We welcome contributions from the community to help improve enterprise code security and data loss prevention.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Issues

- **Bug Reports**: Use [GitHub Issues](https://github.com/27dikshant/classicode/issues) with the "bug" label
- **Feature Requests**: Use [GitHub Discussions](https://github.com/27dikshant/classicode/discussions) for new feature ideas
- **Security Issues**: Follow our [Security Policy](SECURITY.md) for responsible disclosure

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/classicode.git
   cd classicode
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Build the Extension**
   ```bash
   npm run compile
   ```

4. **Development Mode**
   ```bash
   npm run watch
   ```

5. **Test the Extension**
   - Open VS Code in the extension directory: `code .`
   - Press `F5` to launch Extension Development Host
   - Test your changes in the development environment

### Development Guidelines

#### Code Standards

- **TypeScript**: Use strict TypeScript with all compiler checks enabled
- **ESLint**: Follow the existing ESLint configuration
- **Formatting**: Use consistent indentation and formatting
- **Comments**: Include JSDoc comments for public APIs
- **Error Handling**: Implement comprehensive error handling

#### Architecture Principles

- **Security First**: All changes must maintain or improve security posture
- **Performance**: Consider performance impact on large codebases
- **Cross-platform**: Ensure compatibility across macOS, Windows, and Linux
- **Enterprise Ready**: Maintain enterprise-grade reliability and features

#### File Structure

```
src/
├── extension.ts          # Main extension entry point
├── managers/            # Core management classes
├── providers/           # VS Code providers
├── utils/              # Utility functions
└── types/              # TypeScript type definitions
```

### Pull Request Process

1. **Branch Naming**
   ```
   feature/description-of-feature
   bugfix/description-of-bug
   security/description-of-security-fix
   ```

2. **Commit Style**
   ```
   type(scope): description
   
   Examples:
   feat(dlp): add clipboard protection for confidential files
   fix(metadata): resolve xattr corruption on file moves
   security(auth): improve classification verification
   docs(readme): update installation instructions
   ```

3. **Pull Request Requirements**
   - Clear description of changes and motivation
   - Link to related issues or discussions
   - Test your changes thoroughly
   - Update documentation if needed
   - Ensure CI passes (compilation, linting, tests)

4. **Review Process**
   - All PRs require review and approval
   - Security-related changes require additional scrutiny
   - Breaking changes require discussion and planning

### Testing

#### Manual Testing

- Test classification on various file types
- Verify DLP policies work correctly for each classification level
- Test watermark display and configuration
- Validate metadata persistence across file operations

#### Security Testing

- Attempt to bypass DLP controls
- Test metadata tampering scenarios
- Verify integrity verification functions
- Test edge cases in file operations

### Documentation

#### Required Documentation Updates

- Update `README.md` for new features
- Add entries to `CHANGELOG.md`
- Update configuration documentation
- Include JSDoc comments in code

#### Documentation Standards

- Clear, concise language
- Enterprise-focused audience
- Include examples where helpful
- Maintain professional tone

### Licensing

By contributing to ClassiCode, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

#### Contributor License Agreement

- All contributions must be your original work
- You grant the project maintainers perpetual rights to use your contributions
- You confirm you have the right to make the contribution
- Your contribution does not violate any third-party rights

### Security Considerations

Given ClassiCode's security focus, contributors must:

- **Never introduce vulnerabilities**: Security is our top priority
- **Follow secure coding practices**: Input validation, output encoding, etc.
- **Consider attack vectors**: Think like an attacker when reviewing code
- **Maintain confidentiality**: Respect the sensitivity of security discussions

### Getting Help

- **Questions**: Use [GitHub Discussions](https://github.com/27dikshant/classicode/discussions)
- **Bugs**: Create detailed [GitHub Issues](https://github.com/27dikshant/classicode/issues)
- **Security**: Follow the [Security Policy](SECURITY.md)
- **Direct Contact**: Dikshant <27dikshant@gmail.com>

### Recognition

Contributors will be recognized in:

- `CHANGELOG.md` for significant contributions
- GitHub contributor statistics
- Release notes for major contributions
- Project documentation (with permission)

## Development Environment

### VS Code Extensions (Recommended)

- **TypeScript Importer**: Auto import management
- **ESLint**: Real-time linting
- **Prettier**: Code formatting
- **GitLens**: Git integration enhancements

### Debugging

1. Set breakpoints in `src/extension.ts`
2. Press `F5` to start debugging
3. Use the Debug Console in VS Code
4. Test in the Extension Development Host window

### Performance Profiling

Monitor performance impact:

- Use VS Code's built-in performance tools
- Profile file classification operations
- Monitor memory usage during watermarking
- Test with large codebases

---

**Thank you for contributing to ClassiCode and helping make enterprise development more secure!**

For questions about contributing, contact Dikshant <27dikshant@gmail.com>