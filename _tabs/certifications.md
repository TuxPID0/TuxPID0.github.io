---
layout: page
title: Certifications
icon: fas fa-award
order: 4
---

{% assign certs = site.data.certifications %}

## Current Progress

{::nomarkdown}
<div class="cert-roadmap-list">
  {% for item in certs.roadmap %}
  <div class="cert-roadmap-item">
    <div class="cert-roadmap-title">{{ item.title }}</div>
    <span class="cert-roadmap-status status-{{ item.status_type }}">{{ item.status }}</span>
  </div>
  {% endfor %}
</div>
{:/nomarkdown}

## TryHackMe Paths & Events

{::nomarkdown}
<div class="cert-grid">
  {% for cert in certs.tryhackme %}
  <div class="cert-card">
    <div class="cert-thumb">
      <img src="{{ cert.image }}" alt="{{ cert.title }} certificate">
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

## Google Cybersecurity Courses

{::nomarkdown}
{% assign pct = certs.google_courses.completed | times: 100 | divided_by: certs.google_courses.total %}
<div class="cert-track-progress">
  <div class="cert-track-header">
    <span class="cert-track-name">Google Cybersecurity Professional Certificate</span>
    <span class="cert-track-count">{{ certs.google_courses.completed }} / {{ certs.google_courses.total }} Courses ({{ pct }}%)</span>
  </div>
  <div class="cert-progress-bar">
    <div class="cert-progress-fill" style="width: {{ pct }}%;"></div>
  </div>
</div>

<div class="cert-grid">
  {% for cert in certs.google_courses.items %}
  <div class="cert-card">
    <div class="cert-thumb">
      <img src="{{ cert.image }}" alt="{{ cert.title }} certificate">
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

## Community CTFs

{::nomarkdown}
<div class="cert-grid">
  {% for cert in certs.community_ctfs %}
  <div class="cert-card">
    <div class="cert-thumb">
      <img src="{{ cert.image }}" alt="{{ cert.title }} certificate">
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
    </div>
  </div>
  {% endfor %}
</div>
{:/nomarkdown}
