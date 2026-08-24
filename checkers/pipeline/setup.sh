#!/bin/sh
set -eu

IMAGE_IDS="1 2 3 4 5 6"
FIXTURE_DIR="fixture"
PROBE_HOST="www.google.com"

TAR_DIR="tar"
OUTPUT_DIR="images"

mkdir -p "$OUTPUT_DIR" "$TAR_DIR"

for image_id in $IMAGE_IDS; do
    tag="app:v${image_id}"
    tar_file="${TAR_DIR}/app_v${image_id}.tar"
    oci_dir="${OUTPUT_DIR}/v${image_id}"
    
    echo ">>> Building local image: $tag"
    docker build \
        --rm \
        --tag "$tag" \
        --build-arg "BUILD_ID=v${image_id}" \
        --build-arg "PROBE_HOST=${PROBE_HOST}" \
        "$FIXTURE_DIR"
    
    echo ">>> Saving to filesystem: $tar_file"
    docker save -o "$tar_file" "$tag"
    
    echo ">>> Cleaning up docker daemon: removing $tag"
    docker rmi -f "$tag"
    
    echo ">>> Converting to oci "
    skopeo copy "docker-archive:${tar_file}:${tag}" "oci:${oci_dir}";
    
    echo ">>> Done: $oci_dir is ready"
done

echo ">>> Remove tars"
rm -rf ${TAR_DIR}

echo "All images successfully saved to $OUTPUT_DIR/"