import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# Load alerts
alerts_df = pd.read_csv('alerts.csv', parse_dates=['datetime'])

st.title("🔐 Security Alerts Dashboard")

# Summary
st.subheader("Summary by Alert Type")
alert_counts = alerts_df['type'].value_counts()
st.bar_chart(alert_counts)

# Pie Chart
st.subheader("Alerts by Type")
fig1, ax1 = plt.subplots()
ax1.pie(alert_counts, labels=alert_counts.index, autopct='%1.1f%%', startangle=90)
ax1.axis('equal')
st.pyplot(fig1)

# Top IPs
st.subheader("Top 10 IPs with Most Alerts")
top_ips = alerts_df['ip'].value_counts().head(10)
fig3, ax3 = plt.subplots()
top_ips.plot(kind='bar', ax=ax3)
ax3.set_xlabel("IP Address")
ax3.set_ylabel("Alert Count")
ax3.set_title("Top 10 IPs")
st.pyplot(fig3)

# Alerts over time
st.subheader("Alerts Over Time")
alerts_over_time = alerts_df.groupby(alerts_df['datetime'].dt.date).size()
fig4, ax4 = plt.subplots()
ax4.plot(alerts_over_time.index, alerts_over_time.values, marker='o', color='green')
ax4.set_xlabel("Date")
ax4.set_ylabel("Number of Alerts")
ax4.set_title("Alert Trends Over Time")
st.pyplot(fig4)

# Heatmap of alerts per hour
st.subheader("Heatmap of Alerts by Hour")
alerts_df['hour'] = alerts_df['datetime'].dt.hour
hourly_counts = alerts_df.groupby(['hour', 'type']).size().unstack(fill_value=0)
st.write(hourly_counts.style.background_gradient(cmap='YlOrRd'))

# Full Table
st.subheader("All Alerts")
st.dataframe(alerts_df)

# Filtering
st.subheader("Filter by Alert Type")
alert_types = alerts_df['type'].unique()
selected_type = st.selectbox("Select Type", ['All'] + list(alert_types))
if selected_type != 'All':
    st.write(alerts_df[alerts_df['type'] == selected_type])
else:
    st.write(alerts_df)

st.success("Dashboard loaded successfully!")
