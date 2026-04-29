#!/usr/bin/env bash
###############################################################################
# HomelinkWG — publish.sh
# Publie l'image Docker sur Docker Hub (amd64)
#
# Usage :
#   ./publish.sh <dockerhub-username> [tag]
#
# Exemples :
#   ./publish.sh monuser                  → publie monuser/homelinkwg:latest
#   ./publish.sh monuser 1.0.0            → publie monuser/homelinkwg:1.0.0
#   ./publish.sh monuser 1.0.0 --also-latest  → publie :1.0.0 ET :latest
###############################################################################
set -Eeuo pipefail

DOCKERHUB_USER="${1:-}"
TAG="${2:-latest}"
ALSO_LATEST="${3:-}"
IMAGE_NAME="homelinkwg"

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "${DOCKERHUB_USER}" ]]; then
    echo "Usage : $0 <dockerhub-username> [tag] [--also-latest]"
    echo "Exemple : $0 monuser 1.0.0 --also-latest"
    exit 1
fi

FULL_IMAGE="${DOCKERHUB_USER}/${IMAGE_NAME}"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  HomelinkWG — Publication Docker Hub                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Image   : ${FULL_IMAGE}:${TAG}"
echo "  Plateforme : linux/amd64"
[[ "${ALSO_LATEST}" == "--also-latest" && "${TAG}" != "latest" ]] \
    && echo "  Also tag : ${FULL_IMAGE}:latest"
echo ""

# ── S'assurer que buildx est disponible ──────────────────────────────────────
if ! docker buildx version &>/dev/null; then
    echo "[ERROR] docker buildx n'est pas disponible."
    echo "        Installe Docker Desktop ou active BuildKit :"
    echo "        export DOCKER_BUILDKIT=1"
    exit 1
fi

# ── Créer/utiliser un builder multi-plateforme ───────────────────────────────
BUILDER_NAME="homelinkwg-builder"
if ! docker buildx inspect "${BUILDER_NAME}" &>/dev/null; then
    echo "[INFO] Création du builder buildx '${BUILDER_NAME}'..."
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container --use
else
    docker buildx use "${BUILDER_NAME}"
fi

# ── Login Docker Hub ─────────────────────────────────────────────────────────
echo "[INFO] Connexion à Docker Hub en tant que ${DOCKERHUB_USER}..."
docker login --username "${DOCKERHUB_USER}"

# ── Build & Push ─────────────────────────────────────────────────────────────
echo ""
echo "[INFO] Build et push de ${FULL_IMAGE}:${TAG}..."

EXTRA_TAGS=""
if [[ "${ALSO_LATEST}" == "--also-latest" && "${TAG}" != "latest" ]]; then
    EXTRA_TAGS="-t ${FULL_IMAGE}:latest"
fi

docker buildx build \
    --platform linux/amd64 \
    --provenance=false \
    -t "${FULL_IMAGE}:${TAG}" \
    ${EXTRA_TAGS} \
    --push \
    .

echo ""
echo "✅ Image publiée avec succès !"
echo ""
echo "   docker pull ${FULL_IMAGE}:${TAG}"
echo ""
echo "   Voir sur Docker Hub :"
echo "   https://hub.docker.com/r/${FULL_IMAGE}"
echo ""
