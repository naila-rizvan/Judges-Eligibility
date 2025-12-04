
import os
import csv
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, render_template, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

print(generate_password_hash("P9ryg385!5&wer"))
