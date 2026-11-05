<TMPL_INCLUDE NAME="header.tpl">

<div class="container">
  <div class="card">
    <div class="card-body">
      <h3 trspan="accountsList">Application accounts</h3>

      <TMPL_IF NAME="AUTH_ERROR">
        <div class="message message-<TMPL_VAR NAME="AUTH_ERROR_TYPE"> alert">
          <span trmsg="<TMPL_VAR NAME="AUTH_ERROR">"></span>
        </div>
      </TMPL_IF>

      <div id="errmsg" class="alert alert-danger" style="display: none;"></div>

      <input type="hidden" id="token" value="<TMPL_VAR NAME="TOKEN">" />

      <div id="deviceslist"></div>

      <p class="mt-3">
        <button id="adddevice" class="btn btn-primary" trspan="addAccount">Add an account</button>
      </p>

      <div id="newpwd" class="alert alert-info" style="display: none;"></div>
    </div>
  </div>
</div>

<script type="text/javascript" src="<TMPL_VAR NAME="STATIC_PREFIX">common/appaccounts.js?v=<TMPL_VAR NAME="CACHE_TAG">"></script>

<TMPL_INCLUDE NAME="footer.tpl">
