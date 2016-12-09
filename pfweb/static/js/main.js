function save_rules_order() {
	// Store new order in array with old location as value
	var order = [];
	$('#rulestable > tbody > tr').each(function(index, row) {
		order.push(parseInt(row.id.slice(9)));
	});
	
	// Create a form with a JSON array and submit
	form = $('<form method="post" style="display: none;"></form>');
	order_form = $('<input type="hidden" name="save_order" value="' + JSON.stringify(order) + '" />');
	form.append(order_form).submit();
}

function remove_rule(rule) {
	resp = confirm("Are you sure you wish to delete this rule?");

	if(resp == false) {
		return
	}

	location.href = "/firewall/rules/remove/" + rule
}

function remove_table(table) {
	$("#table_" + table).prop("checked", true);

	$("#delete_tables_submit").trigger("click");

	$("#table_" + table).prop("checked", false);
}

function add_address() {
	// Get next ID to use
	field_id = $('#address_fields').children().last().attr('id').split("-")[1];
	new_id = (parseInt(field_id) + 1);
	// Create new dom for addr
	field = $('<div class="col-sm-12 table-addresses" id="addr_container-' + new_id + '">' +
        '<label class="col-sm-2 control-label"></label>' +
        '<div class="col-sm-8">' +
            '<input type="text" class="form-control" id="addr' + new_id + '" name="addr' + new_id + '" value="" placeholder="Address" />' +
        '</div>' +
        '<div class="col-sm-2">' +
            '<button class="btn btn-danger btn-sm" type="button" value="Remove" name="removeaddr' + new_id + '" name="removeaddr' + new_id + '" onclick="table_remove_addr(' + new_id + ');">' +
                '<span class="glyphicon glyphicon-trash"></span>' +
                'Delete' +
            '</button>' +
        '</div>' +
    '</div>');
	// Add to the container
    $("#address_fields").append(field);
}

function table_remove_addr(id) {
	// Only clear the field if only one address
	if($('#address_fields').children().length == 1) {
		$("#addr_container-" + id + " input").val("");
		return
	}

	// Add Label to second field if removing the first address
	if(id == parseInt($('#address_fields').children().first().attr('id').split("-")[1])) {
		$('#address_fields').children().eq(1).children('label').text('Addresses');
	}
	// Remove addr div
	$("#addr_container-" + id).remove();
}

function toggle_fields() {
	// Modify protocol options based on address family
	if($('#af').val() == '*') {
		// Hide ICMP and translation
		$('#icmp_option').hide();
		$('#translation_panel').hide();
		$('#trans_type').val('none');

		if($('#proto').val() == 'ICMP') {
			$('#proto').val('*');
		}

		$.each(['src', 'dst'], function(i, val) {
			if($('#' + val + '_addr_type').val() == 'addrmask') {
				$('#' + val + '_addr_type').val('any');
				addr_type(val, 'any');
			}
			$('#form_' + val + '_addrmask_type').prop('disabled', true);
		});
	}
	else {
		// Show Translation
		$('#translation_panel').show();
		// Only allow NAT with 'out' direction
		if($('#direction').val() == 'out') {
			$('#trans_type_nat').prop('disabled', false);
		}
		else {
			if($('#trans_type').val() == 'NAT') {
				$('#trans_type').val('none');
			}
			$('#trans_type_nat').prop('disabled', true);
		}

		// Show ICMP and addrmask for both IPv4 and IPv6
		$('#icmp_option').show();
		$('#form_src_addrmask_type').prop('disabled', false);
		$('#form_dst_addrmask_type').prop('disabled', false);
	}

	// RDR can only be used with TCP or UDP
	if($('#proto').val() == "TCP" || $('#proto').val() == "UDP") {
		$('#trans_type_rdr').prop('disabled', false);
	}
	else {
		if($('#trans_type').val() == 'RDR') {
			$('#trans_type').val('none');
		}
		$('#trans_type_rdr').prop('disabled', true);
	}

	if($('#proto').val() != "ICMP" || $('#af').val() == '*') {
		// Hide ICMP Type form when protocol isn't ICMP or the AF is Any
		$('#form_icmptype').hide();

		// The ports must be hidden when ICMP is chosen even with AF is Any
		if($('#proto').val() == "ICMP") {
			$('#form_src_port').hide();
			$('#form_dst_port').hide();
		}
		else {
			// Only show ports when ICMP is not the chosen protocol
			$('#form_src_port').show();
			$('#form_dst_port').show();
		}

		return
	}

	// Make sure to hide ports when ICMP type is shown
	$('#form_src_port').hide();
	$('#form_dst_port').hide();
	
	// Show the correct ICMP options in the select for the AF chosen
	if($('#af').val() == 'IPv4') {
		$('#icmptype').show();
		$('#icmp6type').hide();
	}
	else if($('#af').val() == 'IPv6') {
		$('#icmp6type').show();
		$('#icmptype').hide();
	}
	
	// Show the whole ICMP type form
	$('#form_icmptype').show();
}

function port_op(type, port_op) {
	/* Modify port from and to based on port op */

	if(port_op.indexOf('Range') !== -1) {
		$("#" + type + "_port_from").prop('disabled', false);
		$("#" + type + "_port_to").prop('disabled', false);
	}
	else if(port_op == 'Any') {
		$("#" + type + "_port_from").prop('disabled', true);
		$("#" + type + "_port_to").prop('disabled', true);
	}
	else {
		$("#" + type + "_port_from").prop('disabled', false);
		$("#" + type + "_port_to").prop('disabled', true);
	}
}

function addr_type(type, value) {
	if(value == 'addrmask') {
		$("#" + type + "_addr_table").hide();
		$("#" + type + "_addr_iface").hide();
		$("#form_" + type + "_addrmask").show();
	}
	else if(value == 'table') {
		$("#form_" + type + "_addrmask").hide();
		$("#" + type + "_addr_iface").hide();
		$("#" + type + "_addr_table").show();
	}
	else if(value == 'dynif') {
		$("#form_" + type + "_addrmask").hide();
		$("#" + type + "_addr_table").hide();
		$("#" + type + "_addr_iface").show();
	}
	if(value == 'any') {
		$("#" + type + "_addr_table").hide();
		$("#form_" + type + "_addrmask").hide();
		$("#" + type + "_addr_iface").hide();
	}
}

function trans_form_type(value) {
	/* Show or hide fields when selecting different translation types */
	if(value == 'NAT') {
		$("#form_trans_port").hide()
		$("#form_trans_addr_type_dynif").prop('disabled', false);
	}
	else if(value == 'RDR'){
		$("#form_trans_port").show()
		if($('#trans_addr_type').val() == 'dynif') {
			$("#trans_addr_type").val('addrmask');
			addr_type('trans', 'addrmask');
		}
		$("#form_trans_addr_type_dynif").prop('disabled', true);
	}
}

function load_edit_rules_page() {
	/* All actions needed when loading the edit rules page */
	toggle_fields();

	$.each(['src', 'dst'], function(i, val) {
		addr_type(val, $('#' + val + '_addr_type').val());
		port_op(val, $('#' + val + '_port_op option:selected').text());
	});

	addr_type('trans', $('#trans_addr_type').val());
	trans_form_type($('#trans_type').val());
}

function remove_state(item) {
	var data = $(item).data('entry').split('|');

	resp = confirm("Are you sure you wish to delete this state?\n" + data[0] + " -> " + data[1]);

	if(resp == false) {
		return
	}

	var data = $(item).data('entry').split('|');

	$.ajax('/status/states', 
		{
			type: 'post',
			data: {
				action: 'remove',
				src: data[0],
				dst: data[1]
			},
			success: function() {
				$(item).parents('tr').remove();
			},
			error: function(e) {
				$('#modal_alert .modal-title').text("Bad Request");
				$('#modal_alert .modal-body').text(e.responseJSON.message);
				$('#modal_alert').modal()
			}
		}
	);
}