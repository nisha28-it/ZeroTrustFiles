#!/bin/sh
opa run --server --addr=0.0.0.0:8181 /app/policy.rego &
sleep 2
python app.py