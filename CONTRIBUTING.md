# Contributing to AgentShield-CLI

Thank you for your interest in contributing to AgentShield-CLI! 🎉

## 📋 How to Contribute

### Reporting Bugs
1. Check if the issue has already been reported in [Issues](https://github.com/gitstq/AgentShield-CLI/issues)
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment information (OS, Python version)

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`python -m pytest tests/`)
6. Commit with conventional commit format:
   - `feat: add new feature`
   - `fix: fix bug`
   - `docs: update documentation`
   - `refactor: code refactoring`
   - `test: add tests`
7. Push to your branch (`git push origin feature/your-feature`)
8. Create a Pull Request

### Code Style
- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Keep functions focused and small

### Development Setup
```bash
git clone https://github.com/gitstq/AgentShield-CLI.git
cd AgentShield-CLI
python -m pytest tests/ -v
```

## 📄 License
By contributing, you agree that your contributions will be licensed under the MIT License.
