(function () {
  'use strict';

  var token, apiBase;

  function translate(key) {
    var value = window.translate ? window.translate(key) : '';
    return value || key;
  }

  function showError(message) {
    $('#errmsg').text(message).show();
  }

  function failHandler(xhr) {
    var message = translate('error');
    if (xhr.responseJSON && xhr.responseJSON.error) {
      message = xhr.responseJSON.error;
    }
    showError(message);
  }

  function api(path) {
    return apiBase + path;
  }

  function displayPwd(data) {
    var box = $('#newpwd').empty().show();
    [
      ['mail', data.mail],
      ['login', data.uid],
      ['password', data.pwd]
    ].forEach(function (item) {
      var line = $('<p>');
      $('<strong>').text(translate(item[0]) + ': ').appendTo(line);
      $('<span>').text(item[1]).appendTo(line);
      line.appendTo(box);
    });
  }

  function load() {
    $('#newpwd').hide();
    $('#errmsg').hide();
    $.ajax({
      url: api('list'),
      dataType: 'json'
    }).done(function (data) {
      var list = $('#deviceslist').empty();
      if (!data.length) {
        $('<p>').text(translate('noAccount')).appendTo(list);
        return;
      }
      data.forEach(function (dev) {
        var row = $('<div>').addClass('card mb-2');
        var body = $('<div>').addClass(
          'card-body d-flex justify-content-between align-items-center'
        );
        $('<span>').text(dev.name || dev.uid).appendTo(body);
        $('<button>')
          .addClass('btn btn-danger btn-sm')
          .text(translate('delete'))
          .on('click', function () {
            delDevice(dev.uid);
          })
          .appendTo(body);
        row.append(body).appendTo(list);
      });
    }).fail(failHandler);
  }

  function addDevice() {
    var name = window.prompt(translate('accountName'));
    if (name === null) {
      return;
    }
    $.ajax({
      type: 'POST',
      url: api('add'),
      contentType: 'application/json',
      dataType: 'json',
      data: JSON.stringify({ token: token, name: name })
    }).done(function (data) {
      displayPwd(data);
    }).fail(failHandler);
  }

  function delDevice(uid) {
    if (!window.confirm(translate('delAppAccount'))) {
      return;
    }
    $.ajax({
      type: 'POST',
      url: api('del'),
      contentType: 'application/json',
      dataType: 'json',
      data: JSON.stringify({ token: token, uid: uid })
    }).done(load).fail(failHandler);
  }

  $(function () {
    token = $('#token').val();
    apiBase = location.href.replace(/\?.*$/, '').replace(/\/$/, '') + '/';
    $('#adddevice').on('click', addDevice);
    load();
  });
})();
