import streamlit as st
import pandas as pd

from predict import detect_threat




st.set_page_config(
    page_title="TracX - Cyber Threat Detection",
    layout="wide"
)




st.title(
    "🛡️ TracX"
)

st.subheader(
    "AI-Based Detection of Cyber Threats "
    "in Unidirectional IP Traffic"
)

st.write(
    "Hybrid AI-powered network threat "
    "detection and response platform"
)




uploaded_file = st.file_uploader(
    "Upload Network Flow CSV",
    type=["csv"]
)


if uploaded_file is not None:

    data = pd.read_csv(
        uploaded_file
    )

    st.subheader(
        "Network Traffic"
    )

    st.dataframe(
        data,
        use_container_width=True
    )


    

    try:

        results = detect_threat(
            data
        )


        

        total = len(results)

        normal = (
            results["status"]
            == "NORMAL"
        ).sum()

        suspicious = (
            results["status"]
            == "SUSPICIOUS"
        ).sum()

        high_risk = (
            results["status"]
            == "HIGH RISK"
        ).sum()


        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Flows",
            total
        )

        col2.metric(
            "Normal",
            normal
        )

        col3.metric(
            "Suspicious",
            suspicious
        )

        col4.metric(
            "High Risk",
            high_risk
        )


        

        st.subheader(
            "Threat Detection Results"
        )

        st.dataframe(
            results.sort_values(
                "risk_score",
                ascending=False
            ),
            use_container_width=True
        )


        

        high_risk_data = results[
            results["status"]
            == "HIGH RISK"
        ]


        st.subheader(
            "🚨 High Risk Alerts"
        )


        if len(high_risk_data) > 0:

            st.error(
                f"{len(high_risk_data)} "
                "high-risk traffic flows detected."
            )

            st.dataframe(
                high_risk_data,
                use_container_width=True
            )

        else:

            st.success(
                "No high-risk traffic detected."
            )


        

        st.subheader(
            "Risk Score Distribution"
        )

        st.bar_chart(
            results["risk_score"]
        )


        

        csv = results.to_csv(
            index=False
        )

        st.download_button(
            "Download Detection Report",
            csv,
            "threat_detection_report.csv",
            "text/csv"
        )


    except Exception as e:

        st.error(
            f"Error during prediction: {e}"
        )