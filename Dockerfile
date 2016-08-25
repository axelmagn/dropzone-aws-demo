FROM python:3.6-alpine

# expose ports
EXPOSE 80

# install requirements
WORKDIR /tmp
COPY requirements.txt ./
RUN pip install -r requirements.txt

# install app
COPY dzdemo /app
WORKDIR /app

# configure default runtime
ENTRYPOINT ["python", "manage.py"]
CMD ["runserver", "0.0.0.0:80"]

