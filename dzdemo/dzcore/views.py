from base64 import b64decode
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template import loader

from .aws import UploadPolicy, AMZ_ALGORITHM


def upload(request):
    if request.user.is_authenticated:
        policy = UploadPolicy(username=request.user.username)
        context = {
                'bucket_url': policy.bucket_url(),
                'key': policy.upload_key(),
                'acl': policy.upload_acl,
                'policy': policy.get_policy_str(),
                'success_action_redirect': policy.redirect_url,
                'amz_algorithm': AMZ_ALGORITHM,
                'amz_credential': policy.amz_credential(),
                'amz_date': policy.amz_date(),
                'amz_signature': policy.get_signature(),
        }

        template = loader.get_template('upload.html')
        return HttpResponse(template.render(context, request))
    else:
        return redirect('/login/')
