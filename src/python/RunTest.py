from CheckImage import check_image
import os

check_image('docker.io/tremolosecurity/activemq-docker:latest',os.environ['WEBHOOK_URL'])