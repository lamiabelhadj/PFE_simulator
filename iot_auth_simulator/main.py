"""Command-line entry point for the IoT authentication flow simulator."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.simulator_runner import SimulationOptions, run_simulation


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> int:
    """Run the IoT authentication simulator."""
    logger.info("=" * 80)
    logger.info("IoT Authentication Flow Simulator")
    logger.info("=" * 80)
    logger.info("Running normal flow and replay attack scenarios")

    result = run_simulation(SimulationOptions(num_devices=5))

    logger.info("")
    logger.info("=" * 80)
    logger.info("Simulation Summary")
    logger.info("=" * 80)
    logger.info("Total devices simulated: %s", len(result.devices))
    logger.info("Normal flow events: %s", len(result.normal_events))
    logger.info("Replay attack events: %s", len(result.replay_events))
    logger.info("Total events: %s", len(result.all_events))
    logger.info(
        "Normal events anomaly count: %s",
        sum(1 for event in result.normal_events if event.is_anomaly),
    )
    logger.info(
        "Replay events anomaly count: %s",
        sum(1 for event in result.replay_events if event.is_anomaly),
    )
    logger.info("Total anomaly count: %s", result.anomaly_count)
    logger.info("Exported to: %s", result.export_dir)
    logger.info("=" * 80)
    logger.info("Simulator completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
