from base64 import b64encode
from datetime import datetime, timedelta
from django import forms
from django.template import loader
import hashlib
import hmac
import json

from dzdemo.settings import (
        AWS_UPLOAD_BUCKET,
        AWS_UPLOAD_REGION,
        AWS_UPLOAD_PREFIX,
        AWS_UPLOAD_ACL,
        AWS_REDIRECT_URL,
        AWS_POLICY_TEMPLATE,
        AWS_UPLOAD_EXPIRE_DURATION,
        AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY,
)


EXPIRATION_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
AMZ_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
DATE_STAMP_FORMAT = '%Y%m%d'
AMZ_CREDENTIAL_FORMAT = ("{access_key_id}"
                         + "/{date_stamp}"
                         + "/{region}"
                         + "/{service}"
                         + "/aws4_request")
AMZ_ALGORITHM = 'AWS4-HMAC-SHA256'


def sign(key, msg):
    msg = msg.encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).digest()


def hidden_field(*args, **kwargs):
    return forms.CharField(widget=forms.HiddenInput(), **kwargs)


def signature_sanity_check(sts, secret_key, date_stamp, region, service):
    kdate = sign(('AWS4' + secret_key).encode('utf-8'), date_stamp)
    kregion = sign(kdate, region)
    kservice = sign(kregion, service)
    ksigning = sign(kservice, 'aws4_request')

    return hmac.new(ksigning, sts, hashlib.sha256).hexdigest()


def policy_escape(policy_str):
    escapes = {
        "\n": r'\n',
        "\r": r'\r',
        "\\": r'\\',
        "\b": r'\b',
        "\f": r'\f',
        "\t": r'\t',
        "\v": r'\v',
    }
    for k, v in escapes.items():
        policy_str = policy_str.replace(k, v)
    return policy_str


class UploadPolicy(object):
    """AWS S3 Upload policy used in HTTP Post requests to S3"""

    def __init__(
            self,
            username='example_user',
            duration=AWS_UPLOAD_EXPIRE_DURATION,
            bucket=AWS_UPLOAD_BUCKET,
            upload_acl=AWS_UPLOAD_ACL,
            redirect_url=AWS_REDIRECT_URL,
            region=AWS_UPLOAD_REGION,
            access_key_id=AWS_ACCESS_KEY_ID,
            secret_key=AWS_SECRET_ACCESS_KEY,
    ):
        self.date = datetime.utcnow()  # fix at creation date
        self.duration = duration
        self.bucket = bucket
        self.user = username
        self.upload_acl = upload_acl
        self.redirect_url = redirect_url
        self.region = region
        self.service = 's3'
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        pass

    def expiration(self):
        return(self.date + self.duration).strftime(EXPIRATION_FORMAT)

    def date_stamp(self):
        return self.date.strftime(DATE_STAMP_FORMAT)

    def amz_date(self):
        return self.date.strftime(AMZ_DATE_FORMAT)

    def upload_prefix(self):
        return AWS_UPLOAD_PREFIX.format(user=self.user)

    def upload_key(self):
        return self.upload_prefix() + '${filename}'

    def amz_credential(self):
        return AMZ_CREDENTIAL_FORMAT.format(
                access_key_id=self.access_key_id,
                date_stamp=self.date_stamp(),
                region=self.region,
                service=self.service,
        )

    def bucket_url(self):
        return "https://{0}.s3.amazonaws.com/".format(self.bucket)

    def get_data(self):
        context = {
                'expiration': self.expiration(),
                'bucket': self.bucket,
                'upload_prefix': self.upload_prefix(),
                'upload_acl': self.upload_acl,
                'redirect_url': self.redirect_url,
                'aws_credential': self.amz_credential(),
                'aws_date': self.amz_date(),
        }
        template = loader.get_template('policy.json')
        return json.loads(template.render(context))

    def get_policy_str(self, use_b64=True):
        policy = json.dumps(self.get_data()).encode('utf-8')
        if use_b64:
            policy = b64encode(policy)
        return policy

    def get_signing_key(self):
        start_key = ('AWS4' + self.secret_key).encode('utf-8')
        kdate = sign(start_key, self.date_stamp())
        kregion = sign(kdate, self.region)
        kservice = sign(kregion, self.service)
        ksigning = sign(kservice, 'aws4_request')
        # import ipdb; ipdb.set_trace()
        return ksigning

    def get_signature(self):
        return hmac.new(self.get_signing_key(), self.get_policy_str(),
                        hashlib.sha256).hexdigest()
