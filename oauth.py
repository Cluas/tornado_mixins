import functools

from tornado import escape
from tornado.auth import OAuth2Mixin, _auth_return_future, AuthError
from tornado.concurrent import future_set_result_unless_cancelled
from tornado.stack_context import wrap

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

try:
    import urllib.parse as urllib_parse
except ImportError:
    import urllib as urllib_parse

class WexinOAuth2Mixin(OAuth2Mixin):
    """
    WeChat authentication using OAuth2.
    """
    _OAUTH_AUTHORIZE_URL = 'https://open.weixin.qq.com/connect/qrconnect'
    _OAUTH_ACCESS_TOKEN_URL = 'https://api.weixin.qq.com/sns/oauth2/access_token'
    _OAUTH_USERINFO_URL = 'https://api.weixin.qq.com/sns/userinfo'
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'wexin_oauth'

    @_auth_return_future
    def get_authenticated_user(self, code, callback):
        """
        Handles the login for the Wexin user, returning an access token.
        """
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            "code": code,
            "appid": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })

        fut = http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                         method="POST",
                         headers={'Content-Type': 'application/x-www-form-urlencoded'},
                         body=body)
        fut.add_done_callback(wrap(functools.partial(self._on_access_token, callback)))

    def _on_access_token(self, future, response_fut):
        """Callback function for the exchange to the access token."""
        try:
            response = response_fut.result()
        except Exception as e:
            future.set_exception(AuthError('Wexin auth error: %s' % str(e)))
            return

        args = escape.json_decode(response.body)
        if args.get('errcode'):
            future.set_exception(AuthError('Wexin auth error: %s' % str(args['errmsg'])))
            return
        future_set_result_unless_cancelled(future, args)
