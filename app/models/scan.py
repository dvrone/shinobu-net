from datetime import datetime

from . import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Traffic metrics
    total_packets = db.Column(db.Integer, default=0)
    capture_duration = db.Column(db.Float, nullable=True)
    pps = db.Column(db.Float, nullable=True)
    unique_src_ips = db.Column(db.Integer, default=0)
    unique_dst_ips = db.Column(db.Integer, default=0)
    unique_ports = db.Column(db.Integer, default=0)

    # Entropy
    src_entropy = db.Column(db.Float, default=0.0)
    dst_entropy = db.Column(db.Float, default=0.0)
    port_entropy = db.Column(db.Float, default=0.0)

    # Classification
    classification = db.Column(db.String(100), default="Normal")

    # Findings stored as newline-separated text
    findings = db.Column(db.Text, default="")

    def findings_list(self):
        """Return findings as a clean Python list."""
        if not self.findings:
            return []
        return [f for f in self.findings.split("\n") if f.strip()]

    def __repr__(self):
        return f"<Scan {self.id} — {self.filename} — {self.classification}>"
