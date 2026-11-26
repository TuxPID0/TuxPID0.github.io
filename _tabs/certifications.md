---
layout: page
title: Certifications
icon: fas fa-award
order: 4
---

{% assign certs = site.data.certifications %}

<p class="certs-intro">
  Verified certifications, Capture The Flag (CTF) competition results, and hands-on security training milestones focused on <strong>Blue Team &amp; SOC Operations</strong>. Click any certificate preview to inspect it in full resolution.
</p>

{::nomarkdown}
<div class="cert-stats-row">
  {% for stat in certs.stats %}
  <div class="cert-stat-card">
    <div class="cert-stat-icon accent-{{ stat.accent }}">
      <i class="{{ stat.icon }}"></i>
    </div>
    <div>
      <div class="cert-stat-value">{{ stat.value }}</div>
      <div class="cert-stat-label">{{ stat.label }}</div>
    </div>
  </div>
  {% endfor %}
</div>

<div class="cert-badges-grid">
  {% for b in certs.badges %}
  <a href="{{ b.url }}" class="cert-badge-pill" {% if b.url contains 'http' %}target="_blank" rel="noopener noreferrer"{% endif %}>
    <div class="cert-badge-icon badge-{{ b.accent }}">
      <i class="{{ b.icon }}"></i>
    </div>
    <div class="cert-badge-text">
      <div class="cert-badge-title">{{ b.title }}</div>
      <div class="cert-badge-sub">{{ b.subtitle }}</div>
    </div>
  </a>
  {% endfor %}
</div>
{:/nomarkdown}

---

## Competitions & CTF

{::nomarkdown}
<div class="cert-grid">
  {% for cert in certs.competitions %}
  <div class="cert-card">
    <div class="cert-thumb">
      <img src="{{ cert.image }}" alt="{{ cert.title }} - {{ cert.issuer }} certificate">
    </div>
    <div class="cert-body">
      <div class="cert-meta-top">
        <span class="cert-issuer-pill issuer-{{ cert.issuer_type }}">{{ cert.issuer }}</span>
        <span class="cert-date">{{ cert.date }}</span>
      </div>
      <div class="cert-title">{{ cert.title }}</div>
      {% if cert.badge %}
      <span class="cert-subbadge">{{ cert.badge }}</span>
      {% endif %}
      <div class="cert-desc">{{ cert.description }}</div>
      {% if cert.credential_id or cert.verify_url or cert.pdf %}
      <div class="cert-footer">
        {% if cert.credential_id %}
        <span class="cert-id">{{ cert.credential_id }}</span>
        {% endif %}
        <div class="cert-actions">
          {% if cert.verify_url %}
          <a href="{{ cert.verify_url }}" target="_blank" rel="noopener noreferrer" class="cert-btn cert-btn-verify">Verify &#8599;</a>
          {% endif %}
          {% if cert.pdf %}
          <a href="{{ cert.pdf }}" target="_blank" rel="noopener noreferrer" class="cert-btn">PDF</a>
          {% endif %}
        </div>
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</div>
{:/nomarkdown}

---

## TryHackMe Paths & Events

{::nomarkdown}
<div class="cert-grid">
  {% for cert in certs.tryhackme %}
  <div class="cert-card">
    <div class="cert-thumb">
      <img src="{{ cert.image }}" alt="{{ cert.title }} - {{ cert.issuer }} certificate">
    </div>
    <div class="cert-body">
      <div class="cert-meta-top">
        <span class="cert-issuer-pill issuer-{{ cert.issuer_type }}">{{ cert.issuer }}</span>
        <span class="cert-date">{{ cert.date }}</span>
      </div>
      <div class="cert-title">{{ cert.title }}</div>
      {% if cert.badge %}
      <span class="cert-subbadge">{{ cert.badge }}</span>
      {% endif %}
      <div class="cert-desc">{{ cert.description }}</div>
      <div class="cert-footer">
        {% if cert.credential_id %}
        <span class="cert-id">{{ cert.credential_id }}</span>
        {% endif %}
        <div class="cert-actions">
          {% if cert.pdf %}
          <a href="{{ cert.pdf }}" target="_blank" rel="noopener noreferrer" class="cert-btn">PDF</a>
          {% endif %}
        </div>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{:/nomarkdown}

---

## Google Cybersecurity Courses

{::nomarkdown}
{% assign pct = certs.google_courses.completed | times: 100 | divided_by: certs.google_courses.total %}
<div class="cert-track-progress">
  <div class="cert-track-header">
    <span class="cert-track-name">Google Cybersecurity Professional Certificate Specialization</span>
    <span class="cert-track-count">{{ certs.google_courses.completed }} / {{ certs.google_courses.total }} Courses Completed ({{ pct }}%)</span>
  </div>
  <div class="cert-progress-bar">
    <div class="cert-progress-fill" style="width: {{ pct }}%;"></div>
  </div>
</div>

<div class="cert-grid">
  {% for cert in certs.google_courses.items %}
  <div class="cert-card">
    <div class="cert-thumb">
      <img src="{{ cert.image }}" alt="{{ cert.title }} - {{ cert.issuer }} certificate">
    </div>
    <div class="cert-body">
      <div class="cert-meta-top">
        <span class="cert-issuer-pill issuer-{{ cert.issuer_type }}">{{ cert.issuer }}</span>
        <span class="cert-date">{{ cert.date }}</span>
      </div>
      <div class="cert-title">{{ cert.title }}</div>
      {% if cert.badge %}
      <span class="cert-subbadge">{{ cert.badge }}</span>
      {% endif %}
      <div class="cert-desc">{{ cert.description }}</div>
      <div class="cert-footer">
        {% if cert.credential_id %}
        <span class="cert-id">ID: {{ cert.credential_id }}</span>
        {% endif %}
        <div class="cert-actions">
          {% if cert.verify_url %}
          <a href="{{ cert.verify_url }}" target="_blank" rel="noopener noreferrer" class="cert-btn cert-btn-verify">Verify &#8599;</a>
          {% endif %}
          {% if cert.pdf %}
          <a href="{{ cert.pdf }}" target="_blank" rel="noopener noreferrer" class="cert-btn">PDF</a>
          {% endif %}
        </div>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{:/nomarkdown}

---

## In Progress & Upcoming Targets

{::nomarkdown}
<div class="cert-roadmap-list">
  {% for item in certs.roadmap %}
  <div class="cert-roadmap-item">
    <div class="cert-roadmap-top">
      <div class="cert-roadmap-title">{{ item.title }}</div>
      <span class="cert-roadmap-status status-{{ item.status_type }}">{{ item.status }}</span>
    </div>
    <div class="cert-roadmap-detail">{{ item.detail }}</div>
  </div>
  {% endfor %}
</div>
{:/nomarkdown}
