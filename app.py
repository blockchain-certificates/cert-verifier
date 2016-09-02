from flask import Flask, request
import logging

from cert_verifier.verify import verify_v1_2
app = Flask(__name__)

@app.route('/')
def verify():
    return 'Hello, World!'

@app.route('/verification', methods=['GET', 'POST'])
def show_results():
    certificate_json = request.get_json()
    chain = 'testnet'
    result = verify_v1_2(certificate_json, chain)


@app.errorhandler(404)
def page_not_found(error):
    logging.error('Page not found: %s', request.path)
    return 'This page does not exist', 404


@app.errorhandler(500)
def internal_server_error(error):
    logging.error('Server Error: %s', error, exc_info=True)
    return 'Server error: {0}'.format(error), 500


@app.errorhandler(Exception)
def unhandled_exception(e):
    logging.exception('Unhandled Exception: %s', e, exc_info=True)
    return 'Unhandled exception: {0}'.format(e), 500


if __name__ == "__main__":
    app.run()