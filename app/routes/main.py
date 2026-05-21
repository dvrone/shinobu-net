import json
import os

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)
from werkzeug.utils import secure_filename

from ..models import db
from ..models.scan import Scan
from ..services.analyzer import analyze_pcap

main_bp = Blueprint("main", __name__)


def allowed_file(filename):
    allowed = current_app.config["ALLOWED_EXTENSIONS"]
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


# ------------------------------------------
# Home — scan history list
# ------------------------------------------
@main_bp.route("/")
def index():
    scans = Scan.query.order_by(Scan.uploaded_at.desc()).all()
    return render_template("index.html", scans=scans)


# ------------------------------------------
# Upload & Analyze
# ------------------------------------------
@main_bp.route("/upload", methods=["POST"])
def upload():
    if "pcap_file" not in request.files:
        flash("No file part in the request.", "error")
        return redirect(url_for("main.index"))

    file = request.files["pcap_file"]

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.index"))

    if not allowed_file(file.filename):
        flash("Only .pcap and .pcapng files are allowed.", "error")
        return redirect(url_for("main.index"))

    filename = secure_filename(file.filename)
    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    # Run analysis
    try:
        result = analyze_pcap(filepath)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("main.index"))
    except Exception as e:
        flash(f"Analysis failed: {str(e)}", "error")
        return redirect(url_for("main.index"))

    # Save to database
    scan = Scan(
        filename=filename,
        total_packets=result["total_packets"],
        capture_duration=result["capture_duration"],
        pps=result["pps"],
        unique_src_ips=result["unique_src_ips"],
        unique_dst_ips=result["unique_dst_ips"],
        unique_ports=result["unique_ports"],
        src_entropy=result["src_entropy"],
        dst_entropy=result["dst_entropy"],
        port_entropy=result["port_entropy"],
        classification=result["classification"],
        findings="\n".join(result["findings"]),
        top_src_ips=json.dumps(result["top_src_ips"]),
        top_dst_ips=json.dumps(result["top_dst_ips"]),
    )
    db.session.add(scan)
    db.session.commit()

    return redirect(url_for("main.report", scan_id=scan.id))


# ------------------------------------------
# Report — single scan detail
# ------------------------------------------
@main_bp.route("/report/<int:scan_id>")
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template("report.html", scan=scan)


# ------------------------------------------
# Delete a scan
# ------------------------------------------
@main_bp.route("/delete/<int:scan_id>", methods=["POST"])
def delete(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash(f"Scan '{scan.filename}' deleted.", "info")
    return redirect(url_for("main.index"))
