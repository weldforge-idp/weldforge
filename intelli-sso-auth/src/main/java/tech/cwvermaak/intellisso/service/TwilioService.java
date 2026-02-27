package tech.cwvermaak.intellisso.service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TwilioService {

    @Value("${twilio.account-sid}")
    private String accountSid;

    @Value("${twilio.auth-token}")
    private String authToken;

    @Value("${twilio.phone-number}")
    private String fromPhoneNumber;

    @PostConstruct
    public void init() {
        Twilio.init(accountSid, authToken);
    }

    public void sendSms(String to, String messageBody) {
        Message.creator(
                new PhoneNumber(to),
                new PhoneNumber(fromPhoneNumber),
                messageBody
        ).create();
    }

    public void sendWhatsApp(String to, String messageBody) {
        Message.creator(
                new PhoneNumber("whatsapp:" + to),
                new PhoneNumber("whatsapp:" + fromPhoneNumber),
                messageBody
        ).create();
    }
}
