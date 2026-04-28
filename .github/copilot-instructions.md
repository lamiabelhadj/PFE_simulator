<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# IoT Authentication Flow Simulator - Copilot Instructions

## Project Overview
This is an IoT authentication flow simulator that generates synthetic labeled data for ML-based anomaly detection. It models device authentication lifecycles and simulates attack scenarios like replay attacks.

## Architecture
- **Models**: Dataclasses for Device, Token, Session, Event
- **Core**: State machine, flow orchestration, and event generation
- **Components**: Gateway, Auth Server, MQTT Broker simulation
- **Scenarios**: Normal authentication flow and replay attack simulation
- **Exporters**: CSV and JSON output for ML datasets

## Key Design Decisions
1. **PoP (Proof of Possession) is intentionally removed** for this MVP to simplify replay attack modeling
2. **Simple token-based auth** allows clear demonstration of replay attacks
3. **All components are independent** and can be tested separately
4. **Events are fully featured** with 34+ fields for comprehensive ML model training

## File Organization
- `src/models/`: Data structures (Device, Token, Session, Event)
- `src/core/`: State management (StateMachine, FlowEngine, EventGenerator)
- `src/components/`: System components (Gateway, AuthServer, MQTTBroker)
- `src/scenarios/`: Attack and normal flow scenarios
- `src/exporters/`: Data export (CSV, JSON)
- `tests/`: Unit tests for scenarios
- `config/settings.yaml`: Configuration parameters
- `data/generated/`: Generated synthetic datasets

## When Adding Features
1. **New scenarios**: Create in `src/scenarios/`, update `main.py` to call it
2. **New components**: Create in `src/components/`, follow existing patterns
3. **New export formats**: Create in `src/exporters/`, follow exporter interface
4. **New models**: Add to `src/models/` with comprehensive docstrings

## Important Patterns
- All models use Python dataclasses
- Events are self-converting to dicts for export
- State transitions are validated by StateMachine
- Components log their operations for debugging
- All public methods have docstrings with Args/Returns

## Testing
- Unit tests are in `tests/` directory
- Run with: `python tests/test_normal_flow.py` and `python tests/test_replay_attack.py`
- All scenarios should be testable in isolation

## Future Enhancement Areas (marked as TODO in code)
- Add PoP/Proof of Possession implementation
- Add impersonation attack scenario
- Add DoS/flood attack scenario  
- Add ML baseline anomaly detection
- Add realistic latency and energy modeling
- Support configuration-driven scenario execution
