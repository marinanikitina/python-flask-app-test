#!/usr/bin/env python3

import json
import sys

import pandas as pd
import json
import plotly
import plotly.express as px
from flask import Flask, render_template, request
import plotly.graph_objs as go

from library.TimeLibrary import timed_function_beautified

sys.path.append('/library')
import library.RSALibrary as RSALibrary
from library.TimeLibrary import timed_function_beautified

app = Flask(__name__)

n, e, d, p, q = 0, 0, 0, 0, 0
bits = 512
min_e = 3


@app.route('/')
def index():
    global n, e, d, min_e, bits
    context = {
        'n': n,
        'e': e,
        'd': d,
        'min_e': min_e,
        'bits': bits
    }
    return render_template('index.html', **context)


@app.route('/genkeys_pre')
def generate_keys_pre():
    global n, e, d, min_e, bits, p, q
    min_e_param = request.args.get('min_e', '').strip()
    bits_param = request.args.get('bits', '').strip()
    if min_e_param:
        min_e = int(min_e_param)
    if bits_param:
        bits = int(bits_param)
    # (n, e, d), time_needed = timed_function_beautified(RSALibrary.generate_keys, bits, min_e)
    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'min_e': min_e,
        'bits': bits
    }
    return render_template('generate_keys.html', **context)


@app.route('/genkeys')
def generate_keys():
    global n, e, d, min_e, bits, p, q
    min_e_param = request.args.get('min_e', '').strip()
    bits_param = request.args.get('bits', '').strip()
    if min_e_param:
        min_e = int(min_e_param)
    if bits_param:
        bits = int(bits_param)
    if bits > 2048:
        raise Exception("Max bits is 2048")
    (n, e, d, p, q), time_needed = timed_function_beautified(RSALibrary.generate_keys, bits, min_e, True)
    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'min_e': min_e,
        'time_needed': time_needed,
        'bits': bits
    }
    return render_template('generate_keys.html', **context)


@app.route('/enterkeys', methods=['GET', 'POST'])
def enter_keys():
    global n, e, d, min_e, bits, p, q
    saved = False
    if request.method == 'POST':
        n = int(request.form.get('n'))
        e = int(request.form.get('e'))
        d = int(request.form.get('d'))
        p = int(request.form.get('p'))
        q = int(request.form.get('q'))
        saved = True

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'saved': saved
    }
    return render_template('enter_keys.html', **context)


@app.route('/crypto', methods=['GET', 'POST'])
def crypto():
    if n <= 0 or (e <= 0 and d <= 0):
        return index()
    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
    }
    return render_template('crypto.html', **context)


@app.route('/crypto_number', methods=['GET', 'POST'])
def crypto_number():
    if request.method != 'POST':
        return crypto()
    input = int(request.form.get('input')) if request.form.get('input') else 0
    keytype = request.form.get('keytype')
    number_output_crt, time_needed_crt = None, None
    if keytype != 'private':
        keytype = 'public'
        # number_output = RSALibrary.encrypt_number(n, e, input)
        number_output, time_needed = timed_function_beautified(RSALibrary.encrypt_number, n, e, input)

    else:
        number_output, time_needed = timed_function_beautified(RSALibrary.encrypt_number, n, d, input)
        if p > 0 and q > 0:
            number_output_crt, time_needed_crt = timed_function_beautified(RSALibrary.decrypt_number_crt, d, p, q,
                                                                           input)

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'input': input,
        'number_output': number_output,
        'time_needed': time_needed,
        'number_output_crt': number_output_crt,
        'time_needed_crt': time_needed_crt,
        'keytype': keytype
    }
    return render_template('crypto.html', **context)


@app.route('/crypto_text', methods=['GET', 'POST'])
def crypto_text():
    if request.method != 'POST':
        return crypto()
    input_text = request.form.get('input_text')
    keytype = request.form.get('keytype')
    if keytype != 'private':
        keytype = 'public'
        text_output, time_needed = timed_function_beautified(RSALibrary.encrypt_text_v2, n, e, input_text)
    else:
        text_output, time_needed = timed_function_beautified(RSALibrary.encrypt_text_v2, n, d, input_text)

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'input_text': input_text,
        'text_output': text_output,
        'time_needed': time_needed,
        'keytype': keytype
    }
    return render_template('crypto.html', **context)


@app.route('/crypto_text_dec', methods=['GET', 'POST'])
def crypto_text_dec():
    if request.method != 'POST':
        return crypto()
    input_text_dec = int(request.form.get('input_text_dec')) if request.form.get('input_text_dec') else 0
    keytype = request.form.get('keytype')
    print(type(keytype))
    if keytype != 'private':
        keytype = 'public'
        text_output_dec, time_needed = timed_function_beautified(RSALibrary.decrypt_text_v2, n, e, input_text_dec)
    else:
        text_output_dec, time_needed = timed_function_beautified(RSALibrary.decrypt_text_v2, n, d, input_text_dec)

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'input_text_dec': input_text_dec,
        'text_output_dec': text_output_dec,
        'time_needed': time_needed,
        'keytype': keytype
    }

    return render_template('crypto.html', **context)


@app.route('/visual')
def visual():
    x = [64, 128, 256, 512, 1024]

    multipower_enctime = [1.999855042, 5.000352859, 1.002311707, 13.0007267, 42.00315475]
    multiprime_enctime = [0.999689102, 5.01203537, 33.00285339, 42.0024395, 95.00741959]
    crt_enctime = [63.00497055, 95.00646591, 159.0106487, 399.030447, 1109.083176]
    rsa_enctime = [78.00459862, 90.00706673, 165.0128365, 406.0301781, 1131.083965]
    char_enctime = [83.00614357, 135.0224018, 250.0200272, 631.0470104, 1693.109989]
    dependent_enctime = [156.0130119, 270.0023651, 547.0211506, 1577.118874, 5294.175386]

    df_enc = pd.DataFrame({
        'Size of Keys (bits)': x,
        'MultiPower RSA': multipower_enctime,
        'MultiPrime RSA': multiprime_enctime,
        'CRT RSA': crt_enctime,
        'RSA': rsa_enctime,
        'Carmichael RSA': char_enctime,
        'Dependent RSA': dependent_enctime
    })

    fig_enc = px.line(df_enc, x='Size of Keys (bits)', y=df_enc.columns[1:], title='Encryption Time',
                  labels={'value': 'Time (ms)'})
    fig_enc.update_layout(xaxis_range=[0, 1200])
    fig_enc = fig_enc.to_html(full_html=False)

    multipower_dectime = [0.999212027, 1.999616623, 3.000259399, 7.999897003, 19.00300932]
    multiprime_dectime = [1.000165939, 2.001047134, 4.002094269, 9.004211903, 23.99983406]
    crt_dectime = [16.00027084, 25.00867844, 40.99860191, 101.9999981, 276.004075]
    rsa_dectime = [17.99845695, 30.00555038, 56.01243973, 143.0208683, 375.0276566]
    char_dectime = [20.00370026, 34.01999474, 66.02554321, 159.0491772, 421.0968018]
    dependent_dectime = [46.01054192, 83.01558495, 165.0130749, 421.0400581, 1206.142283]

    df_dec = pd.DataFrame({
        'Size of Keys (bits)': x,
        'MultiPower RSA': multipower_dectime,
        'MultiPrime RSA': multiprime_dectime,
        'CRT RSA': crt_dectime,
        'RSA': rsa_dectime,
        'Carmichael RSA': char_dectime,
        'Dependent RSA': dependent_dectime
    })
    fig_dec = px.line(df_dec, x='Size of Keys (bits)', y=df_dec.columns[1:], title='Decryption Time',
                      labels={'value': 'Time (ms)'})
    fig_dec.update_layout(xaxis_range=[0, 1200])
    fig_dec = fig_dec.to_html(full_html=False)

    multipower_keygen = [15.0012, 21.40101, 65.8048, 171.227, 831.6657]
    multiprime_keygen = [218.75, 640.625, 2703.125, 6250, 169328.125]
    crt_keygen = [11.00063324, 32.00221062, 40.625, 206.12375, 728.125]
    rsa_keygen = [15.00201225, 20.99990845, 60.1039, 209.91401, 1059.077978]
    char_keygen = [35.00127792, 34.00063515, 160.0039005, 338.023901, 596.3503]
    dependent_keygen = [15.0008, 24.5006, 51.8034, 145.01, 475.7341]

    df_keygen = pd.DataFrame({
        'Size of Keys (bits)': x,
        'MultiPower RSA': multipower_keygen,
        'MultiPrime RSA': multiprime_keygen,
        'CRT RSA': crt_keygen,
        'RSA': rsa_keygen,
        'Carmichael RSA': char_keygen,
        'Dependent RSA': dependent_keygen
    })

    fig_keygen = px.line(df_keygen, x='Size of Keys (bits)', y=df_keygen.columns[1:], title='Key Generation Time',
                         labels={'value': 'Time (ms)'})
    fig_keygen.update_layout(xaxis_range=[0, 1200])

    fig_keygen = fig_keygen.to_html(full_html=False)

    return render_template('visual.html', fig_enc=fig_enc, fig_dec=fig_dec, fig_keygen=fig_keygen)



if __name__ == '__main__':
    # run() method of Flask class runs the application
    # on the local development server.
    app.run()
# if __name__ == "__main__":
#     port = 5000
#     if len(sys.argv) > 1:
#         port = sys.argv[1]
#         if port.isnumeric():
#             port = int(port)

#     app.run(debug=True, port=port)  # listen on localhost ONLY
#    app.run(debug=True, host='0.0.0.0')    # listen on all public IPs
