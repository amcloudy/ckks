#!/bin/bash
set -e

image_name="openfhe-ckks"
CLEAN_BUILD=false

# Script directory (directory containing this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Script directory: ${SCRIPT_DIR}"

# System RAM in GB
TOTAL_RAM_GB=$(free -g | awk '/Mem:/ {print $2}')
TOTAL_RAM_GB=${TOTAL_RAM_GB:-16}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--name)
      image_name="$2"
      shift 2
      ;;
    -clean|--clean)
      CLEAN_BUILD=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [-n|--name IMAGE_NAME] [-clean|--clean]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "🔧 Building Docker image: $image_name"

if [ "$CLEAN_BUILD" = true ]; then
  docker build --no-cache -t "$image_name" "$SCRIPT_DIR"
else
  docker build -t "$image_name" "$SCRIPT_DIR"
fi

echo "🚀 Starting container from image: $image_name"
docker run \
  -it --rm \
  --name "ckks-dev-container" \
  --shm-size="${TOTAL_RAM_GB}g" \
  -v "$PWD":/workspace \
  --workdir /workspace \
  "$image_name" bash