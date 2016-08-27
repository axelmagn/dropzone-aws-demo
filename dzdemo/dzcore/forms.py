from base64 import b64encode
import json
import os

from django import forms
from django.core.urlresolvers import reverse
from urllib.parse import urljoin

from dzdemo.settings import (AWS_UPLOAD_BUCKET, AWS_UPLOAD_PREFIX, AWS_ACL,
                             AWS_POLICY_TEMPLATE, AWS_ACCESS_KEY_ID,
                             AWS_SECRET_ACCESS_KEY,)
from dzcore.aws import UploadPolicy


class BucketUploadForm(forms.Form):
    """Form to upload to an S3 Bucket"""

    # AWS Form Fields

    """
    key = forms.CharField(widget=forms.HiddenInput())
    AWSAccessKeyId = forms.CharField(widget=forms.HiddenInput())
    acl = forms.CharField(widget=forms.HiddenInput())
    success_action_redirect = forms.CharField(widget=forms.HiddenInput())
    policy = forms.CharField(widget=forms.HiddenInput())
    signature = forms.CharField(widget=forms.HiddenInput())
    """
