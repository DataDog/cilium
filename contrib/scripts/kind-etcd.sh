#!/usr/bin/env bash

set -euo pipefail

# Generate the TLS certificates
generate_certs(){
    openssl genrsa 4096 > $DIR/kvstore-ca-key.pem
    openssl genrsa 4096 > $DIR/kvstore-server-key.pem
    openssl genrsa 4096 > $DIR/kvstore-client-key.pem

    # We reuse the same certificates for all etcd clusters for simplicity,
    # as we are interested in a working setup, not a production-ready one.
    openssl req -new -x509 -nodes -days 1 -subj "/CN=KVStore CA/" \
        -key $DIR/kvstore-ca-key.pem -out $DIR/kvstore-ca-crt.pem
    openssl req -new -x509 -nodes -days 1 -subj "/CN=server/" \
        -addext "subjectAltName=DNS:kvstore1, DNS:kvstore2, DNS:*.mesh.cilium.io" \
        -key $DIR/kvstore-server-key.pem -out $DIR/kvstore-server-crt.pem \
        -CA $DIR/kvstore-ca-crt.pem -CAkey $DIR/kvstore-ca-key.pem
    openssl req -new -x509 -nodes -days 1 -subj "/CN=client/" \
        -key $DIR/kvstore-client-key.pem -out $DIR/kvstore-client-crt.pem \
        -CA $DIR/kvstore-ca-crt.pem -CAkey $DIR/kvstore-ca-key.pem
}

start_etcd(){
    ETCD_VOLUMES=" \
        --volume=$DIR/kvstore-ca-crt.pem:/tmp/tls/ca.crt:ro \
        --volume=$DIR/kvstore-server-crt.pem:/tmp/tls/tls.crt:ro \
        --volume=$DIR/kvstore-server-key.pem:/tmp/tls/tls.key:ro \
    "

    ETCD_FLAGS=" \
        --client-cert-auth \
        --trusted-ca-file=/tmp/tls/ca.crt \
        --cert-file=/tmp/tls/tls.crt \
        --key-file=/tmp/tls/tls.key \
        --listen-client-urls=https://0.0.0.0:2379 \
        --advertise-client-urls=https://0.0.0.0:2379 \
    "

    ETCD_IMAGE="gcr.io/etcd-development/etcd:v3.5.12@sha256:cebe24b890641de3e7ff8a640c4597bdda321090c29f4dedcedaa8cadbbe08e1"

    docker run --name kvstore1 --detach --network=kind-cilium ${ETCD_VOLUMES} ${ETCD_IMAGE} etcd ${ETCD_FLAGS}
    docker run --name kvstore2 --detach --network=kind-cilium ${ETCD_VOLUMES} ${ETCD_IMAGE} etcd ${ETCD_FLAGS}
}

set_connection_params(){
    echo "settings= \
        --set etcd.enabled=true \
        --set etcd.endpoints=https://kvstore1:2379 \
        --set etcd.ssl=true \
        --set identityAllocationMode=kvstore \
    "

    SECRET_PATH=$DIR/cilium-etcd-secrets.yaml
    echo "cilium_etcd_secrets_path=$SECRET_PATH"
    kubectl --context=kind-clustermesh1 -n kube-system create secret generic cilium-etcd-secrets  \
        --from-file etcd-client-ca.crt=$DIR/kvstore-ca-crt.pem \
        --from-file etcd-client.crt=$DIR/kvstore-client-crt.pem \
        --from-file etcd-client.key=$DIR/kvstore-client-key.pem

    kubectl --context=kind-clustermesh2 -n kube-system create secret generic cilium-etcd-secrets  \
        --from-file etcd-client-ca.crt=$DIR/kvstore-ca-crt.pem \
        --from-file etcd-client.crt=$DIR/kvstore-client-crt.pem \
        --from-file etcd-client.key=$DIR/kvstore-client-key.pem
}

get_clustermesh_params(){
    SETTINGS=""
    declare -i NUM_CLUSTERS=2
    CLUSTER_PREFIX=kvstore
    for i in {1..${NUM_CLUSTERS}}; do
        IP=$(docker inspect --format '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${CLUSTER_PREFIX}$i)
        SETTINGS="$SETTINGS \
        --set clustermesh.config.clusters[$(( i-1 ))].ips={$IP} \
        --set clustermesh.config.clusters[$(( i-1 ))].port=2379 \
        --set clustermesh.config.clusters[$(( i-1 ))].tls.caCert=$(base64 -w0 $DIR/kvstore-ca-crt.pem) \
        --set clustermesh.config.clusters[$(( i-1 ))].tls.cert=$(base64 -w0 $DIR/kvstore-client-crt.pem) \
        --set clustermesh.config.clusters[$(( i-1 ))].tls.key=$(base64 -w0 $DIR/kvstore-client-key.pem) \
        "
    done

    echo "settings=$SETTINGS"
    export SETTINGS
}

DIR=$(mktemp -d)

generate_certs
start_etcd
set_connection_params
get_clustermesh_params



