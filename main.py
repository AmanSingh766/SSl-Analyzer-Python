import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from ssl_analyzer import SSLAnalyzer
import csv
from fpdf import FPDF
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import io

# Page configuration
st.set_page_config(
    page_title="SSL Certificate Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 0rem 1rem;
    }
    .stAlert {
        margin-top: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = SSLAnalyzer()

def create_gauge_chart(score, title):
    """Create a gauge chart for security score"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 24}},
        delta={'reference': 80},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 50], 'color': '#FF6B6B'},
                {'range': [50, 70], 'color': '#FFD93D'},
                {'range': [70, 90], 'color': '#6BCB77'},
                {'range': [90, 100], 'color': '#4D96FF'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
    return fig

def export_to_csv(results):
    """Export results to CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    headers = ['Hostname', 'Status', 'Common Name', 'Issuer', 'Valid Until', 
               'Days Remaining', 'Security Score', 'Grade', 'Certificate Status']
    writer.writerow(headers)
    
    # Data
    for result in results:
        if result['status'] == 'success':
            writer.writerow([
                result['hostname'],
                result['status'],
                result['common_name'],
                result['issuer_name'],
                result['valid_until'],
                result['days_remaining'],
                result['security_score'],
                st.session_state.analyzer.get_security_grade(result['security_score']),
                result['certificate_status']
            ])
        else:
            writer.writerow([
                result['hostname'],
                'error',
                'N/A',
                'N/A',
                'N/A',
                'N/A',
                0,
                'F',
                'Error'
            ])
    
    return output.getvalue()

def export_to_pdf(results):
    """Export results to PDF"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, 'SSL Certificate Analysis Report', 0, 1, 'C')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
    pdf.ln(10)
    
    for result in results:
        if result['status'] == 'success':
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, f"Website: {result['hostname']}", 0, 1)
            pdf.set_font("Arial", '', 10)
            
            data = [
                f"Common Name: {result['common_name']}",
                f"Issuer: {result['issuer_name']}",
                f"Valid Until: {result['valid_until']}",
                f"Days Remaining: {result['days_remaining']}",
                f"Security Score: {result['security_score']}/100",
                f"Grade: {st.session_state.analyzer.get_security_grade(result['security_score'])}",
                f"Status: {result['certificate_status']}",
                f"Protocol: {result['protocol_version']}",
                f"Cipher: {result['cipher_suite']}"
            ]
            
            for line in data:
                pdf.cell(0, 6, line, 0, 1)
            pdf.ln(5)
        else:
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, f"Website: {result['hostname']}", 0, 1)
            pdf.set_font("Arial", '', 10)
            pdf.cell(0, 6, f"Error: {result['error']}", 0, 1)
            pdf.ln(5)
    
    return pdf.output(dest='S').encode('latin-1')

def send_email_alert(result, email_config):
    """Send email alert for expiring certificates"""
    try:
        msg = MIMEMultipart()
        msg['From'] = email_config['from_email']
        msg['To'] = email_config['to_email']
        msg['Subject'] = f"SSL Certificate Alert: {result['hostname']}"
        
        body = f"""
        SSL Certificate Alert
        
        Website: {result['hostname']}
        Status: {result['certificate_status']}
        Days Remaining: {result['days_remaining']}
        Valid Until: {result['valid_until']}
        Security Score: {result['security_score']}/100
        
        Please renew the certificate soon to avoid service disruption.
        
        ---
        Generated by SSL Certificate Analyzer
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
        server.starttls()
        server.login(email_config['from_email'], email_config['password'])
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return False

# Main App
st.title("🔒 SSL Certificate Analyzer")
st.markdown("### Analyze SSL certificates and identify security issues")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    scan_mode = st.radio(
        "Scan Mode",
        ["Single Website", "Batch Scan", "Scan History"]
    )
    
    st.markdown("---")
    
    # Email Configuration
    with st.expander("📧 Email Alert Settings"):
        enable_email = st.checkbox("Enable Email Alerts")
        if enable_email:
            smtp_server = st.text_input("SMTP Server", "smtp.gmail.com")
            smtp_port = st.number_input("SMTP Port", value=587)
            from_email = st.text_input("From Email")
            to_email = st.text_input("To Email")
            email_password = st.text_input("Email Password", type="password")
            alert_threshold = st.slider("Alert if days remaining <", 1, 30, 10)
    
    st.markdown("---")
    st.info("💡 **Tip**: Check multiple websites at once using Batch Scan mode!")

# Main Content
if scan_mode == "Single Website":
    col1, col2 = st.columns([3, 1])
    
    with col1:
        website_url = st.text_input(
            "Enter Website URL",
            placeholder="example.com or https://example.com",
            help="Enter the domain name or full URL"
        )
    
    with col2:
        st.write("")
        st.write("")
        analyze_button = st.button("🔍 Analyze", use_container_width=True)
    
    if analyze_button and website_url:
        with st.spinner(f"Analyzing {website_url}..."):
            result = st.session_state.analyzer.analyze_website(website_url)
            
            # Add to history
            result['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.scan_history.append(result)
            
            if result['status'] == 'success':
                # Security Score Gauge
                st.plotly_chart(
                    create_gauge_chart(result['security_score'], "Security Score"),
                    use_container_width=True
                )
                
                # Metrics Row
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    grade = st.session_state.analyzer.get_security_grade(result['security_score'])
                    st.metric("Security Grade", grade)
                
                with col2:
                    st.metric("Days Remaining", result['days_remaining'])
                
                with col3:
                    st.metric("Certificate Status", result['certificate_status'])
                
                with col4:
                    st.metric("Protocol", result['protocol_version'])
                
                # Alerts
                if result['is_expired']:
                    st.error("⚠️ **CRITICAL**: Certificate has expired!")
                elif result['days_remaining'] <= 10:
                    st.error(f"⚠️ **WARNING**: Certificate expires in {result['days_remaining']} days!")
                elif result['days_remaining'] <= 30:
                    st.warning(f"⚠️ Certificate expires in {result['days_remaining']} days")
                
                if result['is_self_signed']:
                    st.warning("⚠️ **Self-Signed Certificate**: Not trusted by browsers")
                
                if result['is_weak_cipher']:
                    st.warning("⚠️ **Weak Cipher Detected**: Upgrade to stronger encryption")
                
                # Detailed Information
                st.markdown("---")
                st.subheader("📋 Certificate Details")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Basic Information**")
                    st.write(f"**Common Name:** {result['common_name']}")
                    st.write(f"**Organization:** {result['organization']}")
                    st.write(f"**Serial Number:** {result['serial_number']}")
                    st.write(f"**Valid From:** {result['valid_from']}")
                    st.write(f"**Valid Until:** {result['valid_until']}")
                
                with col2:
                    st.markdown("**Issuer Information**")
                    st.write(f"**Issuer Name:** {result['issuer_name']}")
                    st.write(f"**Issuer Organization:** {result['issuer_org']}")
                    st.write(f"**Self-Signed:** {'Yes' if result['is_self_signed'] else 'No'}")
                    st.write(f"**Cipher Suite:** {result['cipher_suite']}")
                    st.write(f"**Weak Cipher:** {'Yes' if result['is_weak_cipher'] else 'No'}")
                
                # SANs
                if result['san_list']:
                    st.markdown("**Subject Alternative Names (SANs)**")
                    st.write(", ".join(result['san_list'][:10]))
                
                # Email Alert
                if enable_email and result['days_remaining'] <= alert_threshold and result['days_remaining'] > 0:
                    email_config = {
                        'smtp_server': smtp_server,
                        'smtp_port': smtp_port,
                        'from_email': from_email,
                        'to_email': to_email,
                        'password': email_password
                    }
                    if send_email_alert(result, email_config):
                        st.success("✅ Email alert sent successfully!")
                
            else:
                st.error(f"❌ Failed to analyze {website_url}")
                st.error(f"**Error:** {result['error']}")

elif scan_mode == "Batch Scan":
    st.subheader("📊 Batch Scan Multiple Websites")
    
    input_method = st.radio("Input Method", ["Text Input", "File Upload"])
    
    websites = []
    
    if input_method == "Text Input":
        websites_text = st.text_area(
            "Enter websites (one per line)",
            placeholder="google.com\namazon.com\nfacebook.com",
            height=150
        )
        if websites_text:
            websites = [w.strip() for w in websites_text.split('\n') if w.strip()]
    
    else:
        uploaded_file = st.file_uploader("Upload text file with websites", type=['txt'])
        if uploaded_file:
            websites = [line.decode('utf-8').strip() for line in uploaded_file.readlines() if line.strip()]
    
    if websites:
        st.info(f"📋 {len(websites)} websites ready to scan")
        
        if st.button("🚀 Start Batch Scan", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            for idx, website in enumerate(websites):
                status_text.text(f"Scanning {website}... ({idx+1}/{len(websites)})")
                result = st.session_state.analyzer.analyze_website(website)
                result['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                results.append(result)
                st.session_state.scan_history.append(result)
                progress_bar.progress((idx + 1) / len(websites))
            
            status_text.text("✅ Scan completed!")
            
            # Summary Statistics
            st.markdown("---")
            st.subheader("📊 Scan Summary")
            
            successful_scans = [r for r in results if r['status'] == 'success']
            failed_scans = [r for r in results if r['status'] == 'error']
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Scanned", len(results))
            with col2:
                st.metric("Successful", len(successful_scans))
            with col3:
                st.metric("Failed", len(failed_scans))
            with col4:
                if successful_scans:
                    avg_score = sum(r['security_score'] for r in successful_scans) / len(successful_scans)
                    st.metric("Avg Security Score", f"{avg_score:.1f}")
                else:
                    st.metric("Avg Security Score", "N/A")
            
            # Results Table
            if successful_scans:
                st.markdown("---")
                st.subheader("📋 Detailed Results")
                
                df_data = []
                for r in successful_scans:
                    df_data.append({
                        'Website': r['hostname'],
                        'Grade': st.session_state.analyzer.get_security_grade(r['security_score']),
                        'Score': r['security_score'],
                        'Status': r['certificate_status'],
                        'Days Left': r['days_remaining'],
                        'Issuer': r['issuer_name'],
                        'Protocol': r['protocol_version']
                    })
                
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True)
                
                # Visualizations
                col1, col2 = st.columns(2)
                
                with col1:
                    # Score distribution
                    fig = px.histogram(df, x='Score', nbins=20, 
                                     title='Security Score Distribution',
                                     labels={'Score': 'Security Score'},
                                     color_discrete_sequence=['#667eea'])
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Status distribution
                    status_counts = df['Status'].value_counts()
                    fig = px.pie(values=status_counts.values, names=status_counts.index,
                               title='Certificate Status Distribution',
                               color_discrete_sequence=px.colors.qualitative.Set3)
                    st.plotly_chart(fig, use_container_width=True)
            
            # Export Options
            st.markdown("---")
            st.subheader("📥 Export Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                csv_data = export_to_csv(results)
                st.download_button(
                    label="📄 Download CSV Report",
                    data=csv_data,
                    file_name=f"ssl_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            
            with col2:
                pdf_data = export_to_pdf(results)
                st.download_button(
                    label="📑 Download PDF Report",
                    data=pdf_data,
                    file_name=f"ssl_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

else:  # Scan History
    st.subheader("📜 Scan History")
    
    if st.session_state.scan_history:
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.scan_history = []
                st.rerun()
        
        # Display history
        for idx, result in enumerate(reversed(st.session_state.scan_history[-20:])):
            with st.expander(f"{result['hostname']} - {result.get('timestamp', 'N/A')}"):
                if result['status'] == 'success':
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Security Score", result['security_score'])
                    with col2:
                        st.metric("Days Remaining", result['days_remaining'])
                    with col3:
                        st.metric("Status", result['certificate_status'])
                    
                    st.write(f"**Issuer:** {result['issuer_name']}")
                    st.write(f"**Valid Until:** {result['valid_until']}")
                else:
                    st.error(f"Error: {result['error']}")
    else:
        st.info("No scan history yet. Start analyzing websites to see history here!")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: gray;'>
        <p>🔒 SSL Certificate Analyzer | Built with Streamlit & Python</p>
        <p>Analyze SSL certificates • Detect security issues • Ensure web safety</p>
    </div>
    """,
    unsafe_allow_html=True
)