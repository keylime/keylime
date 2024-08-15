from keylime.web.base import Controller
from keylime import web_util

class AgentsController(Controller):
    # GET /v3.0/agents/:id/
    def show(self, req, params):
        web_util.echo_json_response(req, 200, "Success", {"msg": "success"})
    
    # POST /v3.0/agents/
    # In v2.1, this action is handled by a POST to /3.0/agents/:id but this is semantically incorrect
    def create(self, req, params):
        pass

    # DELETE /v3.0/agents/:id/
    def delete(self, req, params):
        pass
    
    # POST /v3.0/agents/:id/reactivate/
    # In v2.1, this action is handled by a PUT instead but this is semantically incorrect
    # @pull_only
    def reactivate(self, req, params):
        pass
    
    # POST /v3.0/agents/:id/stop/
    # In v2.1, this action is handled by a PUT instead but this is semantically incorrect
    # @pull_only
    def stop(self, req, params):
        pass