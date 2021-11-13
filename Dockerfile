FROM python:3.8
# That image is a heckin chonker but the other ones are missing libraries

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .

# Hacky way to keep the container alive
ENTRYPOINT ["tail"]
CMD ["-f","/dev/null"]