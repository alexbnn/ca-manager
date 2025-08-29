from flask import Flask, render_template

app = Flask(__name__)

@app.route('/test-js')
def test_js():
    return render_template('test-js.html')

if __name__ == '__main__':
    print("Test this page at: http://localhost:5001/test-js")
    app.run(port=5001, debug=True)