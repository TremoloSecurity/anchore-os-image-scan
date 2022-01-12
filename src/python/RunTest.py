from CheckImage import check_image_grype
import os

check_image_grype('docker.io/tremolosecurity/openunison-k8s:latest',os.environ['WEBHOOK_URL'])