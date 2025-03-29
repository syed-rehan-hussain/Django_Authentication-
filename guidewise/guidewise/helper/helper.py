from datetime import datetime, timedelta
import os
import jwt


def createJWTtoken(payload):
    try:
        # tz=settings.TIME_ZONE
        expiry = datetime.now() + timedelta(days=1)
        refreshExpiry = datetime.now() + timedelta(days=7)

        token = jwt.encode({'email': payload['email'], 'expiry': expiry.timestamp()}, os.getenv("SECRET_KEY"),  algorithm='HS256')
        refreshToken = jwt.encode({'email': payload['email'],'expiry': refreshExpiry.timestamp()}, str(os.environ.get('REFRESH_SECRETKEY')), algorithm='HS256')
        return {'access_token': token, 'refresh_token': refreshToken}

    except Exception as e:
        raise Exception(str(e))
