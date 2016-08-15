from google.appengine.ext import ndb
import webapp2


ERROR_404 = '''
<html>
 <head>
  <title>404 Not Found</title>
 </head>
 <body>
  <h1>404 Not Found</h1>
  The resource could not be found.<br /><br />
 </body>
</html>
'''


class ACMEChallengeResponse(ndb.Model):
    challenge = ndb.StringProperty()
    response = ndb.StringProperty()

    @classmethod
    def query_challenge(cls, challenge):
        return cls.query(ACMEChallengeResponse.challenge == challenge).get()


class ACMEHandler(webapp2.RequestHandler):
    def get(self, challenge):
        result = ACMEChallengeResponse.query_challenge(challenge)
        if result:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.write(result.response)
        else:
            self.error(404)
            self.response.write(ERROR_404)


app = webapp2.WSGIApplication([
    ('/.well-known/acme-challenge/(.*)', ACMEHandler)
])
