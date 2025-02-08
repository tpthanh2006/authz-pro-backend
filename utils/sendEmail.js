const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendEmail = async (send_to, sent_from, reply_to, templateId, dynamic_template_data) => {
  try {
    const msg = {
      to: send_to,
      from: sent_from,
      template_id: templateId,
      dynamic_template_data: dynamic_template_data,
      replyTo: reply_to
    };

    await sgMail.send(msg);
    return true;
  } catch (error) {
    console.error("SendGrid Error:", error);
    throw new Error(error.message);
  }
};

module.exports = sendEmail;