(function () {
  'use strict';

  (function () {
    $(window).on("load", function () {
      var form = document.getElementById('sshCaForm');
      if (!form) return;
      var resultDiv = document.getElementById('sshCaResult');
      var errorDiv = document.getElementById('sshCaError');
      var certTextarea = document.getElementById('sshCertificate');
      var keyIdSpan = document.getElementById('sshKeyId');
      var principalsSpan = document.getElementById('sshPrincipals');
      var validUntilSpan = document.getElementById('sshValidUntil');
      var copyBtn = document.getElementById('copySshCert');
      var errorMsg = document.getElementById('sshCaErrorMessage');
      var validitySelect = document.getElementById('sshValidity');

      // Filter validity options based on max validity
      if (validitySelect) {
        var maxValidity = parseInt(validitySelect.dataset.maxValidity) || 365;
        var options = validitySelect.querySelectorAll('option');
        var lastValidOption = null;
        options.forEach(function (option) {
          var value = parseInt(option.value);
          if (value > maxValidity) {
            option.remove();
          } else {
            lastValidOption = option;
          }
        });

        // Select the highest valid option if the default was removed
        var selectedOption = validitySelect.querySelector('option[selected]');
        if (!selectedOption && lastValidOption) {
          lastValidOption.selected = true;
        }
      }
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        resultDiv.classList.add('d-none');
        errorDiv.classList.add('d-none');
        var publicKey = document.getElementById('sshPublicKey').value.trim();
        var validityDays = parseInt(validitySelect.value);
        if (!publicKey) {
          errorMsg.textContent = 'Please paste your SSH public key';
          errorDiv.classList.remove('d-none');
          return;
        }
        $.ajax({
          type: "POST",
          url: scriptname + 'ssh/sign',
          contentType: "application/json",
          data: JSON.stringify({
            public_key: publicKey,
            validity_days: validityDays
          }),
          dataType: "json",
          success: function success(data) {
            if (data.error) {
              errorMsg.textContent = data.error;
              errorDiv.classList.remove('d-none');
            } else {
              certTextarea.value = data.certificate;
              keyIdSpan.textContent = data.key_id;
              principalsSpan.textContent = data.principals.join(', ');
              validUntilSpan.textContent = data.valid_until;
              resultDiv.classList.remove('d-none');
            }
          },
          error: function error(xhr, status, _error) {
            var msg = _error || status;
            try {
              var resp = JSON.parse(xhr.responseText);
              if (resp.error) msg = resp.error;
            } catch (e) {}
            errorMsg.textContent = msg;
            errorDiv.classList.remove('d-none');
          }
        });
      });

      // Copy button
      if (copyBtn) {
        copyBtn.addEventListener('click', function () {
          certTextarea.select();
          certTextarea.setSelectionRange(0, 99999);
          navigator.clipboard.writeText(certTextarea.value).then(function () {
            var originalHtml = copyBtn.innerHTML;
            copyBtn.innerHTML = '<span class="fa fa-check"></span> Copied!';
            setTimeout(function () {
              copyBtn.innerHTML = originalHtml;
            }, 2000);
          });
        });
      }
    });
  })();

})();
