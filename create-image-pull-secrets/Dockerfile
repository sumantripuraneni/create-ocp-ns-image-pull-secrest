FROM registry.redhat.io/rhel8/python-38

COPY create-image-pull-secrets.py requirements.txt .

RUN pip install -r requirements.txt

ENTRYPOINT ["python","create-image-pull-secrets.py"]
